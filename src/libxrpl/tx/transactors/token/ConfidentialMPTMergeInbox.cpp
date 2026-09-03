#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
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

[[nodiscard]] Slice
u256Slice(uint256 const& value)
{
    return Slice{value.data(), value.size()};
}

[[nodiscard]] std::optional<cm::Point>
toPoint(Slice const data)
{
    if (!cm::isValidCompressedPoint(data))
        return std::nullopt;
    cm::Point out{};
    std::memcpy(out.data(), data.data(), cm::kPointBytes);
    return out;
}

[[nodiscard]] std::optional<cm::Scalar>
toScalar(Slice const data)
{
    if (!cm::isValidScalar(data))
        return std::nullopt;
    cm::Scalar out{};
    std::memcpy(out.data(), data.data(), cm::kScalarBytes);
    return out;
}

/** Canonical EncZero under `pk` for an MPT confidential balance.
 *
 * Spec EncZero domain is Account || Issuer || Currency. MPT holder balances
 * are keyed only by MPTokenIssuanceID (no Issuer+Currency pair), so that
 * issuance ID is the token-domain input here.
 *
 * Interface assumption: preferred crypto helper would be
 * `encryptedZero(Point, AccountID, MPTID)`. Until provided, derive r via
 * SHA-512-Half and call `encryptZero`.
 */
[[nodiscard]] std::optional<cm::Ciphertext>
mptEncryptedZero(cm::Point const& pk, AccountID const& account, MPTID const& issuanceID)
{
    static constexpr std::string_view kTag = "EncZero";
    auto const digest =
        sha512Half(Slice{kTag.data(), kTag.size()}, account, issuanceID);
    auto const r = toScalar(u256Slice(digest));
    if (!r)
        return std::nullopt;
    return cm::encryptZero(pk, *r);
}

}  // namespace

std::uint32_t
ConfidentialMPTMergeInbox::getFlagsMask(PreflightContext const& ctx)
{
    return tfUniversalMask;
}

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const& ctx)
{
    // featureConfidentialTransfer is gated by the TRANSACTION macro
    // (temDISABLED when disabled).
    // Issuer rejection requires ledger state (preclaim).
    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
{
    auto const account = ctx.tx[sfAccount];
    auto const issuanceID = ctx.tx[sfMPTokenIssuanceID];

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

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance))
        return tecNO_PERMISSION;

    if (sleIssuance->isFieldPresent(sfAuditorEncryptionKey) &&
        !sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
        return tecNO_PERMISSION;

    if (sleIssuance->isFlag(lsfMPTRequireAuth) && !sleMpt->isFlag(lsfMPTAuthorized))
        return tecNO_AUTH;

    if (sleMpt->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    if (!cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceInbox))) ||
        !cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending))) ||
        !cm::isValidCompressedPoint(makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey))))
        return tecNO_PERMISSION;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const account = accountID_;
    auto const issuanceID = ctx_.tx[sfMPTokenIssuanceID];

    auto sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    if (account == (*sleIssuance)[sfIssuer])
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const holderPk = toPoint(makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey)));
    auto const inbox =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceInbox)));
    auto const spending =
        cm::parseCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
    if (!holderPk || !inbox || !spending)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // EncZero inbox/spending is a valid no-op: add still runs, inbox resets
    // to EncZero, and version still advances (wraps at UINT32_MAX -> 0).
    auto const merged = cm::ciphertextAdd(*spending, *inbox);
    if (!merged)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const resetInbox = mptEncryptedZero(*holderPk, account, issuanceID);
    if (!resetInbox)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    sleMpt->setFieldVL(sfConfidentialBalanceSpending, makeSlice(*merged));
    sleMpt->setFieldVL(sfConfidentialBalanceInbox, makeSlice(*resetInbox));

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].value_or(0);
    sleMpt->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

    view().update(sleMpt);
    return tesSUCCESS;
}

void
ConfidentialMPTMergeInbox::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTMergeInbox::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
