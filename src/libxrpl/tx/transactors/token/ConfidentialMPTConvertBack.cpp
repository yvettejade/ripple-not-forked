#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>

namespace xrpl {
namespace {

namespace cm = confidential_mpt;

/*
 * Concurrent crypto lives in <xrpl/crypto/confidential_mpt.h> (task text named
 * ConfidentialMPT.h). Surface used here:
 *   isValidCompressedPoint, isValidScalar, parseCiphertext,
 *   ciphertextC1/C2, verifyCiphertext, ciphertextSub, encryptZero,
 *   splitConvertBackProof, verifyConvertBackSigma, pointSub, pointMulBase,
 *   ConvertBackPublicInput, verifySingleBulletproof.
 */

[[nodiscard]] Slice
asSlice(uint256 const& value)
{
    return Slice{value.data(), value.size()};
}

[[nodiscard]] std::optional<cm::Point>
toPoint(Slice const data)
{
    if (!cm::isValidCompressedPoint(data))
        return std::nullopt;
    cm::Point point{};
    std::memcpy(point.data(), data.data(), cm::kPointBytes);
    return point;
}

[[nodiscard]] std::optional<cm::Scalar>
toScalar(Slice const data)
{
    if (!cm::isValidScalar(data))
        return std::nullopt;
    cm::Scalar scalar{};
    std::memcpy(scalar.data(), data.data(), cm::kScalarBytes);
    return scalar;
}

[[nodiscard]] cm::Scalar
scalarFromAmount(std::uint64_t amount)
{
    cm::Scalar s{};
    for (std::size_t i = 0; i < 8; ++i)
        s[31 - i] = static_cast<std::uint8_t>((amount >> (8 * i)) & 0xff);
    return s;
}

[[nodiscard]] bool
verifyAmountCiphertext(
    cm::Point const& pk,
    Slice const ciphertext,
    std::uint64_t amount,
    cm::Scalar const& blinding)
{
    auto const ct = cm::parseCiphertext(ciphertext);
    return ct && cm::verifyCiphertext(pk, *ct, amount, blinding);
}

/** TransactionContextID for ConvertBack (Updated_ConfidentialMPT §4.7).
 *
 * TxSpecific := Account || CBS_Version(A). Account is repeated as the
 * "Receiver" slot so ConvertBack keeps the same outer context layout as
 * Send/Clawback (Updated §4.7: "Receiver is set equal to Account").
 */
[[nodiscard]] uint256
makeConvertBackContext(STTx const& tx, std::uint32_t cbsVersion)
{
    return sha512Half(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
        tx.getAccountID(sfAccount),
        tx[sfMPTokenIssuanceID],
        tx.getSeqProxy().value(),
        tx.getAccountID(sfAccount),
        cbsVersion);
}

/**
 * Single 64-bit Bulletproof over PC_rem = PC_b - m·G (688 bytes).
 * Context matches the ConvertBack compact sigma TransactionContextID.
 */
[[nodiscard]] bool
verifyConvertBackBulletproof(
    cm::Point const& remainderCommitment,
    Slice rangeProof,
    Slice context) noexcept
{
    if (rangeProof.size() != ConfidentialMPTConvertBack::kBulletproofBytes)
        return false;
    return cm::verifySingleBulletproof(remainderCommitment, rangeProof, context);
}

}  // namespace

std::uint32_t
ConfidentialMPTConvertBack::getFlagsMask(PreflightContext const& ctx)
{
    return tfUniversalMask;
}

NotTEC
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    auto const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    auto const checkCt = [](Slice const data) -> NotTEC {
        if (data.size() != cm::kCiphertextBytes || !cm::parseCiphertext(data))
            return temBAD_CIPHERTEXT;
        return tesSUCCESS;
    };

    // Use operator[] so Slice points into STTx-owned STBlob storage.
    // makeSlice(getFieldVL(...)) dangles: getFieldVL returns a temporary Blob.
    if (auto const r = checkCt(ctx.tx[sfHolderEncryptedAmount]); !isTesSuccess(r))
        return r;
    if (auto const r = checkCt(ctx.tx[sfIssuerEncryptedAmount]); !isTesSuccess(r))
        return r;
    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const r = checkCt(ctx.tx[sfAuditorEncryptedAmount]); !isTesSuccess(r))
            return r;
    }

    if (!cm::isValidScalar(asSlice(ctx.tx[sfBlindingFactor])))
        return temMALFORMED;

    auto const commitment = ctx.tx[sfBalanceCommitment];
    if (commitment.size() != cm::kPointBytes || !cm::isValidCompressedPoint(commitment))
        return temMALFORMED;

    // splitConvertBackProof returns Slices into the input; dangling input
    // would leave sigma/rangeProof pointing at a destroyed temporary Blob.
    auto const split = cm::splitConvertBackProof(ctx.tx[sfZKProof]);
    if (!split || split->sigma.size() != cm::kConvertBackSigmaBytes ||
        split->rangeProof.size() != kBulletproofBytes)
        return temMALFORMED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvertBack::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
{
    auto const account = ctx.tx[sfAccount];
    auto const issuanceID = ctx.tx[sfMPTokenIssuanceID];
    auto const amount = ctx.tx[sfMPTAmount];

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    // Issuer cannot convert back; check before MPToken lookup (xls-0096).
    if (account == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    bool const hasAuditorAmount = ctx.tx.isFieldPresent(sfAuditorEncryptedAmount);
    if (hasAuditorKey != hasAuditorAmount)
        return tecNO_PERMISSION;
    if (hasAuditorKey && !sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
        return tecNO_PERMISSION;

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    if (coa < amount)
        return tecINSUFFICIENT_FUNDS;

    // SPEC INCONSISTENCY (xls-0096): names terFROZEN, absent in this tree.
    // Existing MPT freeze/lock checks use tecLOCKED.
    if (sleMpt->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    auto const holderPk = toPoint((*sleMpt)[sfHolderEncryptionKey]);
    auto const issuerPk = toPoint((*sleIssuance)[sfIssuerEncryptionKey]);
    auto const blinding = toScalar(asSlice(ctx.tx[sfBlindingFactor]));
    if (!holderPk || !issuerPk || !blinding)
        return tecBAD_PROOF;

    if (!verifyAmountCiphertext(*holderPk, ctx.tx[sfHolderEncryptedAmount], amount, *blinding) ||
        !verifyAmountCiphertext(*issuerPk, ctx.tx[sfIssuerEncryptedAmount], amount, *blinding))
        return tecBAD_PROOF;

    if (hasAuditorKey)
    {
        auto const auditorPk = toPoint((*sleIssuance)[sfAuditorEncryptionKey]);
        if (!auditorPk ||
            !verifyAmountCiphertext(
                *auditorPk, ctx.tx[sfAuditorEncryptedAmount], amount, *blinding))
            return tecBAD_PROOF;
    }

    auto const spending = cm::parseCiphertext((*sleMpt)[sfConfidentialBalanceSpending]);
    auto const commitment = toPoint(ctx.tx[sfBalanceCommitment]);
    auto const split = cm::splitConvertBackProof(ctx.tx[sfZKProof]);
    if (!spending || !commitment || !split)
        return tecBAD_PROOF;

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].value_or(0);
    auto const context = makeConvertBackContext(ctx.tx, version);

    cm::ConvertBackPublicInput const input{
        .holderKey = *holderPk,
        .balanceC1 = cm::ciphertextC1(*spending),
        .balanceC2 = cm::ciphertextC2(*spending),
        .balanceCommitment = *commitment};

    if (!cm::verifyConvertBackSigma(input, split->sigma, asSlice(context)))
        return tecBAD_PROOF;

    // PC_rem = PC_b - m·G. When m == 0, m·G is identity so rem == PC_b.
    cm::Point remainderCommitment = *commitment;
    if (amount != 0)
    {
        auto const amountPoint = cm::pointMulBase(scalarFromAmount(amount));
        if (!amountPoint)
            return tecBAD_PROOF;
        auto const rem = cm::pointSub(*commitment, *amountPoint);
        if (!rem)
            return tecBAD_PROOF;
        remainderCommitment = *rem;
    }

    if (!verifyConvertBackBulletproof(remainderCommitment, split->rangeProof, asSlice(context)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = accountID_;
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const holderCt = cm::parseCiphertext(tx[sfHolderEncryptedAmount]);
    auto const issuerCt = cm::parseCiphertext(tx[sfIssuerEncryptedAmount]);
    auto const spending = cm::parseCiphertext((*sleMpt)[sfConfidentialBalanceSpending]);
    auto const issuerBal = cm::parseCiphertext((*sleMpt)[sfIssuerEncryptedBalance]);
    if (!holderCt || !issuerCt || !spending || !issuerBal)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const newSpending = cm::ciphertextSub(*spending, *holderCt);
    auto const newIssuerBal = cm::ciphertextSub(*issuerBal, *issuerCt);
    if (!newSpending || !newIssuerBal)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    sleMpt->setFieldVL(sfConfidentialBalanceSpending, makeSlice(*newSpending));
    sleMpt->setFieldVL(sfIssuerEncryptedBalance, makeSlice(*newIssuerBal));

    if (tx.isFieldPresent(sfAuditorEncryptedAmount) &&
        sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
    {
        auto const auditorCt = cm::parseCiphertext(tx[sfAuditorEncryptedAmount]);
        auto const auditorBal = cm::parseCiphertext((*sleMpt)[sfAuditorEncryptedBalance]);
        if (!auditorCt || !auditorBal)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        auto const newAuditorBal = cm::ciphertextSub(*auditorBal, *auditorCt);
        if (!newAuditorBal)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfAuditorEncryptedBalance, makeSlice(*newAuditorBal));
    }

    auto const publicBal = (*sleMpt)[~sfMPTAmount].valueOr(0);
    if (publicBal > kMaxMpTokenAmount - amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    // SoeDefault: ValueProxy removes the field when the value is 0.
    (*sleMpt)[sfMPTAmount] = publicBal + amount;

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].valueOr(0);
    if (coa < amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    // SPEC INCONSISTENCY (xls-0096 §10.5 vs §10.7):
    // §10.5 decreases only ConfidentialOutstandingAmount (COA) and increases the
    // holder's public MPTAmount — OutstandingAmount (OA) is unchanged, which matches
    // the OA = public + confidential invariant. §10.7's edge-case narrative incorrectly
    // states "OA ↓". This implementation follows §10.5 and leaves OA untouched.
    // SoeDefault: ValueProxy removes the field when the value is 0.
    (*sleIssuance)[sfConfidentialOutstandingAmount] = coa - amount;

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].valueOr(0);
    sleMpt->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

    view().update(sleMpt);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvertBack::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTConvertBack::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
