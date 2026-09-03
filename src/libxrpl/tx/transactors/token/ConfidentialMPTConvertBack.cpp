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

#include <cstring>
#include <cstdint>
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
 *   ConvertBackPublicInput.
 * Bulletproof verification is intentionally absent — see blocker below.
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

/** TransactionContextID for ConvertBack (Updated_ConfidentialMPT §4.7). */
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
 * BLOCKER: no 688-byte ConvertBack Bulletproof verifier exists.
 *
 * Spec requires verifying 0 <= b-m < 2^64 over PC_rem = PC_b - m·G. The crypto
 * module only splits ZKProof (`ProofPrefixView::rangeProof` untouched). Do not
 * fake acceptance.
 *
 * Assumed future signature (not present):
 *   bool verifyConvertBackBulletproof(Point const& remainderCommitment,
 *                                     Slice rangeProof688) noexcept;
 */
[[nodiscard]] bool
verifyConvertBackBulletproof(cm::Point const& /*remainderCommitment*/, Slice rangeProof) noexcept
{
    if (rangeProof.size() != ConfidentialMPTConvertBack::kBulletproofBytes)
        return false;
    return false;
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

    if (auto const r = checkCt(makeSlice(ctx.tx.getFieldVL(sfHolderEncryptedAmount)));
        !isTesSuccess(r))
        return r;
    if (auto const r = checkCt(makeSlice(ctx.tx.getFieldVL(sfIssuerEncryptedAmount)));
        !isTesSuccess(r))
        return r;
    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const r = checkCt(makeSlice(ctx.tx.getFieldVL(sfAuditorEncryptedAmount)));
            !isTesSuccess(r))
            return r;
    }

    if (!cm::isValidScalar(asSlice(ctx.tx[sfBlindingFactor])))
        return temMALFORMED;

    auto const commitment = makeSlice(ctx.tx.getFieldVL(sfBalanceCommitment));
    if (commitment.size() != cm::kPointBytes || !cm::isValidCompressedPoint(commitment))
        return temMALFORMED;

    auto const split = cm::splitConvertBackProof(makeSlice(ctx.tx.getFieldVL(sfZKProof)));
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

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (account == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

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

    // XLS-0096 says terFROZEN, which does not exist in this tree. Existing
    // MPT freeze/lock checks use tecLOCKED.
    if (sleMpt->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    auto const holderPk = toPoint(makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey)));
    auto const issuerPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfIssuerEncryptionKey)));
    auto const blinding = toScalar(asSlice(ctx.tx[sfBlindingFactor]));
    if (!holderPk || !issuerPk || !blinding)
        return tecBAD_PROOF;

    if (!verifyAmountCiphertext(
            *holderPk,
            makeSlice(ctx.tx.getFieldVL(sfHolderEncryptedAmount)),
            amount,
            *blinding) ||
        !verifyAmountCiphertext(
            *issuerPk,
            makeSlice(ctx.tx.getFieldVL(sfIssuerEncryptedAmount)),
            amount,
            *blinding))
        return tecBAD_PROOF;

    if (hasAuditorKey)
    {
        auto const auditorPk =
            toPoint(makeSlice(sleIssuance->getFieldVL(sfAuditorEncryptionKey)));
        if (!auditorPk ||
            !verifyAmountCiphertext(
                *auditorPk,
                makeSlice(ctx.tx.getFieldVL(sfAuditorEncryptedAmount)),
                amount,
                *blinding))
            return tecBAD_PROOF;
    }

    auto const spending =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
    auto const commitment = toPoint(makeSlice(ctx.tx.getFieldVL(sfBalanceCommitment)));
    auto const split = cm::splitConvertBackProof(makeSlice(ctx.tx.getFieldVL(sfZKProof)));
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

    // PC_rem = PC_b - m·G (for a future Bulletproof verifier). Encoding m as a
    // scalar is best-effort; the Bulletproof check fails closed regardless.
    cm::Point remainderCommitment = *commitment;
    if (auto const amountPoint = cm::pointMulBase(scalarFromAmount(amount)))
    {
        if (auto const rem = cm::pointSub(*commitment, *amountPoint))
            remainderCommitment = *rem;
    }

    if (!verifyConvertBackBulletproof(remainderCommitment, split->rangeProof))
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

    auto const holderCt =
        cm::parseCiphertext(makeSlice(tx.getFieldVL(sfHolderEncryptedAmount)));
    auto const issuerCt =
        cm::parseCiphertext(makeSlice(tx.getFieldVL(sfIssuerEncryptedAmount)));
    auto const spending =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
    auto const issuerBal =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
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
        auto const auditorCt =
            cm::parseCiphertext(makeSlice(tx.getFieldVL(sfAuditorEncryptedAmount)));
        auto const auditorBal =
            cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfAuditorEncryptedBalance)));
        if (!auditorCt || !auditorBal)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        auto const newAuditorBal = cm::ciphertextSub(*auditorBal, *auditorCt);
        if (!newAuditorBal)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfAuditorEncryptedBalance, makeSlice(*newAuditorBal));
    }

    auto const publicBal = (*sleMpt)[~sfMPTAmount].value_or(0);
    if (publicBal > kMaxMpTokenAmount - amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldU64(sfMPTAmount, publicBal + amount);

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    if (coa < amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleIssuance->setFieldU64(sfConfidentialOutstandingAmount, coa - amount);

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].value_or(0);
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
