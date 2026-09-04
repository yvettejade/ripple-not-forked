#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <memory>
#include <optional>

namespace xrpl {
namespace {

[[nodiscard]] std::optional<Secp256k1Point>
parsePk(Blob const& key)
{
    return Secp256k1Point::parse(makeSlice(key));
}

}  // namespace

bool
ConfidentialMPTMergeInbox::checkExtraFeatures(PreflightContext const& ctx)
{
    return ctx.rules.enabled(featureConfidentialTransfer);
}

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const& ctx)
{
    // Amendment also gated via transactions.macro feature + checkExtraFeatures.
    // Cannot know issuer without ledger; issuer checks are in preclaim.
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    // Spec §14: confidential merge costs 10× the reference base fee.
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const account = tx[sfAccount];
    auto const issuanceID = tx[sfMPTokenIssuanceID];

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    // Spec §9.2.1.2 says temMALFORMED for issuer. Preclaim returning tem* is
    // frowned upon here (no existing MPT txs do so); use tecNO_PERMISSION.
    if (account == (*sleIssuance)[sfIssuer])
        return tecNO_PERMISSION;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    if (sleIssuance->isFlag(lsfMPTRequireAuth) && !sleMpt->isFlag(lsfMPTAuthorized))
        return tecNO_AUTH;

    if (sleMpt->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = tx[sfAccount];
    auto const issuanceID = tx[sfMPTokenIssuanceID];

    auto const sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const issuer = (*sleIssuance)[sfIssuer];
    auto const holderPk = parsePk(sleMpt->getFieldVL(sfHolderEncryptionKey));
    if (!holderPk)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // spending = spending ⊕ inbox
    auto const merged = homomorphicAddCiphertexts(
        makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)),
        makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceInbox)));
    if (!merged)
        return tefINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldVL(sfConfidentialBalanceSpending, *merged);

    // inbox = EncZero(holder). Issuer/auditor mirrors are totals and unchanged.
    auto zero = encZero(account, issuer, issuanceID, *holderPk);
    if (!zero)
        return tefINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldVL(sfConfidentialBalanceInbox, *zero);

    // version += 1, wrap at 2^32. EncZero no-op merge still increments.
    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].valueOr(0);
    (*sleMpt)[sfConfidentialBalanceVersion] = version + 1;

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
