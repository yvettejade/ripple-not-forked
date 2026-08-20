#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <limits>

namespace xrpl {

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const&)
{
    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const account = ctx.tx[sfAccount];
    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const token = ctx.view.read(keylet::mptoken(id, account));
    if (!issuance || !token)
        return tecOBJECT_NOT_FOUND;
    if (account == issuance->at(sfIssuer))
        return tecNO_PERMISSION;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;
    if (!token->isFieldPresent(sfConfidentialBalanceSpending) ||
        !token->isFieldPresent(sfConfidentialBalanceInbox) ||
        !token->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;
    if (auto const ter = requireAuth(ctx.view, MPTIssue{id}, account);
        !isTesSuccess(ter))
        return ter;
    if (isFrozen(ctx.view, account, MPTIssue{id}))
        return tecLOCKED;
    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(
    ReadView const& view,
    STTx const& tx)
{
    return confidential_mpt::proofBaseFee(view, tx);
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto token = view().peek(keylet::mptoken(id, accountID_));
    if (!token)
        return tefINTERNAL;

    auto const spending = confidential_mpt::addCiphertexts(
        token->at(sfConfidentialBalanceSpending),
        token->at(sfConfidentialBalanceInbox));
    auto const inbox = confidential_mpt::canonicalZero(
        accountID_, id, token->at(sfHolderEncryptionKey));
    if (!spending || !inbox)
        return tefINTERNAL;

    // An encryption of zero is a plaintext identity but not a ciphertext
    // identity. XLS-0096 called this "unchanged"; the question was raised and
    // clarified to perform the homomorphic addition, which rerandomizes CB_S.
    token->setFieldVL(sfConfidentialBalanceSpending, *spending);
    token->setFieldVL(sfConfidentialBalanceInbox, *inbox);
    token->setFieldU32(
        sfConfidentialBalanceVersion,
        token->at(sfConfidentialBalanceVersion) + 1u);
    view().update(token);
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
