#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

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
 * Concurrent crypto (<xrpl/crypto/confidential_mpt.h>; task text: ConfidentialMPT.h):
 *   isValidCompressedPoint, parseCiphertext, ciphertextC1/C2,
 *   verifyClawback, ClawbackPublicInput, encryptZero.
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

/** Canonical EncZero for an MPT confidential balance under `pk`. */
[[nodiscard]] std::optional<cm::Ciphertext>
mptEncryptedZero(cm::Point const& pk, AccountID const& account, MPTID const& issuanceID)
{
    static constexpr std::string_view kTag = "EncZero";
    auto const digest = sha512Half(makeSlice(kTag), account, issuanceID);
    auto const r = toScalar(asSlice(digest));
    if (!r)
        return std::nullopt;
    return cm::encryptZero(pk, *r);
}

/** TransactionContextID for Clawback (Updated_ConfidentialMPT §5.6). */
[[nodiscard]] uint256
makeClawbackContext(STTx const& tx)
{
    // TxSpecific := Holder || 0 (version binding intentionally omitted).
    return sha512Half(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
        tx.getAccountID(sfAccount),
        tx[sfMPTokenIssuanceID],
        tx.getSeqProxy().value(),
        tx.getAccountID(sfHolder),
        std::uint32_t{0});
}

}  // namespace

std::uint32_t
ConfidentialMPTClawback::getFlagsMask(PreflightContext const& ctx)
{
    return tfUniversalMask;
}

NotTEC
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfAccount] == ctx.tx[sfHolder])
        return temMALFORMED;

    auto const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    auto const proof = makeSlice(ctx.tx.getFieldVL(sfZKProof));
    if (proof.size() != cm::kClawbackProofBytes)
        return temMALFORMED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const issuer = ctx.tx[sfAccount];
    auto const holder = ctx.tx[sfHolder];
    auto const issuanceID = ctx.tx[sfMPTokenIssuanceID];
    auto const amount = ctx.tx[sfMPTAmount];

    if (!ctx.view.exists(keylet::account(holder)))
        return tecNO_TARGET;

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (issuer != (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    if (!sleIssuance->isFlag(lsfMPTCanClawback))
        return tecNO_PERMISSION;

    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, holder));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (hasAuditorKey && !sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
        return tecNO_PERMISSION;

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    if (amount > coa)
        return tecINSUFFICIENT_FUNDS;

    auto const outstanding = (*sleIssuance)[sfOutstandingAmount];
    if (amount > outstanding)
        return tecINSUFFICIENT_FUNDS;

    auto const issuerPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfIssuerEncryptionKey)));
    auto const issuerBal =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
    if (!issuerPk || !issuerBal)
        return tecBAD_PROOF;

    cm::ClawbackPublicInput const input{
        .issuerKey = *issuerPk,
        .c1 = cm::ciphertextC1(*issuerBal),
        .c2 = cm::ciphertextC2(*issuerBal),
        .m = amount};

    auto const context = makeClawbackContext(ctx.tx);
    if (!cm::verifyClawback(input, makeSlice(ctx.tx.getFieldVL(sfZKProof)), asSlice(context)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const& tx = ctx_.tx;
    auto const holder = tx[sfHolder];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto sleMpt = view().peek(keylet::mptoken(issuanceID, holder));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const holderPk = toPoint(makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey)));
    auto const issuerPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfIssuerEncryptionKey)));
    if (!holderPk || !issuerPk)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const zeroHolder = mptEncryptedZero(*holderPk, holder, issuanceID);
    auto const zeroIssuer = mptEncryptedZero(*issuerPk, holder, issuanceID);
    if (!zeroHolder || !zeroIssuer)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    sleMpt->setFieldVL(sfConfidentialBalanceSpending, makeSlice(*zeroHolder));
    sleMpt->setFieldVL(sfConfidentialBalanceInbox, makeSlice(*zeroHolder));
    sleMpt->setFieldVL(sfIssuerEncryptedBalance, makeSlice(*zeroIssuer));

    if (sleIssuance->isFieldPresent(sfAuditorEncryptionKey) &&
        sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
    {
        auto const auditorPk =
            toPoint(makeSlice(sleIssuance->getFieldVL(sfAuditorEncryptionKey)));
        if (!auditorPk)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        auto const zeroAuditor = mptEncryptedZero(*auditorPk, holder, issuanceID);
        if (!zeroAuditor)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfAuditorEncryptedBalance, makeSlice(*zeroAuditor));
    }

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].value_or(0);
    sleMpt->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

    // Burn: reduce COA and OA. Do not create/credit an issuer MPToken balance.
    // Supplemental "public reserve" language is interpreted through XLS-33 OA
    // semantics (outstanding supply contracts when confidential value is burned).
    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    auto const outstanding = (*sleIssuance)[sfOutstandingAmount];
    if (amount > coa || amount > outstanding)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    sleIssuance->setFieldU64(sfConfidentialOutstandingAmount, coa - amount);
    sleIssuance->setFieldU64(sfOutstandingAmount, outstanding - amount);

    view().update(sleMpt);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTClawback::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTClawback::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
