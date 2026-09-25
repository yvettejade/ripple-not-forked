#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTHelpers.h>

#include <cstdint>
#include <memory>

namespace xrpl {

using namespace confidential;
namespace cm = confidential_mpt;

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cm::baseFee(view, tx);
}

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const& ctx)
{
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() == ctx.tx[sfAccount])
        return temMALFORMED;
    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
{
    auto const account = ctx.tx[sfAccount];
    auto const id = ctx.tx[sfMPTokenIssuanceID];

    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const mptoken = ctx.view.read(keylet::mptoken(id, account));
    if (!issuance || !mptoken)
        return tecOBJECT_NOT_FOUND;

    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    if (!cm::isInitialized(*mptoken))
        return tecNO_PERMISSION;

    if (auto const ter = requireAuth(ctx.view, MPTIssue{id}, account); !isTesSuccess(ter))
        return ter;

    if (isFrozen(ctx.view, account, MPTIssue{id}))
        return tecLOCKED;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    if (MPTIssue{id}.getIssuer() == accountID_)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto mptoken = view().peek(keylet::mptoken(id, accountID_));
    if (!mptoken)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const key = cm::point(*mptoken, sfHolderEncryptionKey);
    auto const spending = cm::ciphertext(*mptoken, sfConfidentialBalanceSpending);
    auto const inbox = cm::ciphertext(*mptoken, sfConfidentialBalanceInbox);
    if (!key || !spending || !inbox)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // Section 9.3: move the whole inbox into the spending balance, reset the
    // inbox to the canonical encrypted zero and bump the version (wrapping).
    // The sum is the identity only if the holder cancelled its own
    // randomness in a Convert; it cannot be stored, so the merge fails.
    if (auto const ter = cm::store(*mptoken, sfConfidentialBalanceSpending, *spending + *inbox);
        !isTesSuccess(ter))
        return ter;
    if (auto const ter =
            cm::store(*mptoken, sfConfidentialBalanceInbox, encryptedZero(accountID_, id, *key));
        !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE
    mptoken->setFieldU32(
        sfConfidentialBalanceVersion,
        static_cast<std::uint32_t>(mptoken->getFieldU32(sfConfidentialBalanceVersion) + 1));
    view().update(mptoken);
    return tesSUCCESS;
}

void
ConfidentialMPTMergeInbox::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
    // ValidConfidentialMPToken checks this transaction's supply change.
}

bool
ConfidentialMPTMergeInbox::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // ValidConfidentialMPToken checks this transaction's supply change.
    return true;
}

}  // namespace xrpl
