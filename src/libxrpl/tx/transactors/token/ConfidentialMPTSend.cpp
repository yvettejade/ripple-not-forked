#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

namespace xrpl {

NotTEC
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfAccount] == ctx.tx[sfDestination])
        return temMALFORMED;
    if (ctx.tx[sfZKProof].size() != confidential_mpt::kSendProofBytes)
        return temMALFORMED;
    if (!confidential_mpt::validPoint(ctx.tx[sfBalanceCommitment]) ||
        !confidential_mpt::validPoint(ctx.tx[sfAmountCommitment]))
        return temMALFORMED;
    if (!confidential_mpt::validCiphertext(ctx.tx[sfSenderEncryptedAmount]) ||
        !confidential_mpt::validCiphertext(
            ctx.tx[sfDestinationEncryptedAmount]) ||
        !confidential_mpt::validCiphertext(ctx.tx[sfIssuerEncryptedAmount]) ||
        (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount) &&
         !confidential_mpt::validCiphertext(ctx.tx[sfAuditorEncryptedAmount])))
        return temBAD_CIPHERTEXT;
    return tesSUCCESS;
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const account = ctx.tx[sfAccount];
    auto const destination = ctx.tx[sfDestination];
    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    if (!ctx.view.exists(keylet::account(destination)))
        return tecNO_TARGET;
    if (!issuance)
        return tecOBJECT_NOT_FOUND;
    if (account == issuance->at(sfIssuer))
        return tecNO_PERMISSION;
    if (!issuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance) ||
        issuance->at(sfTransferFee) != 0u)
        return tecNO_PERMISSION;

    auto const sender = ctx.view.read(keylet::mptoken(id, account));
    auto const receiver = ctx.view.read(keylet::mptoken(id, destination));
    auto initialized = [](std::shared_ptr<SLE const> const& token) {
        return token && token->isFieldPresent(sfHolderEncryptionKey) &&
            token->isFieldPresent(sfConfidentialBalanceSpending) &&
            token->isFieldPresent(sfConfidentialBalanceInbox) &&
            token->isFieldPresent(sfIssuerEncryptedBalance);
    };
    if (!initialized(sender) || !initialized(receiver))
        return tecNO_PERMISSION;
    if (isAnyFrozen(ctx.view, {account, destination}, MPTIssue{id}))
        return tecLOCKED;
    if (auto const ter = requireAuth(ctx.view, MPTIssue{id}, account);
        !isTesSuccess(ter))
        return ter;
    if (auto const ter = requireAuth(ctx.view, MPTIssue{id}, destination);
        !isTesSuccess(ter))
        return ter;

    auto const auditorRequired =
        issuance->isFieldPresent(sfAuditorEncryptionKey);
    if (auditorRequired != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    // The installed standard libsecp256k1 has no Bulletproof module. This
    // dependency question was raised; fail closed until the specified
    // 192-byte sigma and 754-byte aggregated Bulletproof verifier are available.
    // Do not invent a fake verifier for the under-specified Send compact sigma.
    return tecBAD_PROOF;
}

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return confidential_mpt::proofBaseFee(view, tx);
}

TER
ConfidentialMPTSend::doApply()
{
    return tefINTERNAL;
}

void
ConfidentialMPTSend::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTSend::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
