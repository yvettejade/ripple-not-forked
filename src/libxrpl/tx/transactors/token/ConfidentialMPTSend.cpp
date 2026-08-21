#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/ledger/helpers/CredentialHelpers.h>
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
    if (auto const err = credentials::checkFields(ctx.tx, ctx.j);
        !isTesSuccess(err))
        return err;
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
    // XLS-0096 §8.3.1.2. Issuer identity is on-ledger, so this lives in
    // preclaim rather than preflight.
    if (account == issuance->at(sfIssuer))
        return temMALFORMED;
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
    // XLS-0096 named this terFROZEN; this tree already has terLOCKED for MPT
    // locks and no terFROZEN enumerator.
    if (isAnyFrozen(ctx.view, {account, destination}, MPTIssue{id}))
        return terLOCKED;
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

    if (auto const err =
            credentials::valid(ctx.tx, ctx.view, ctx.tx[sfAccount], ctx.j);
        !isTesSuccess(err))
        return err;

    // Compact Send sigma (192 bytes) and the 754-byte aggregated Bulletproof
    // are specified only as wire sizes. XLS-0096 gave neither the Fiat–Shamir
    // transcript nor the sigma equations, and the in-tree libsecp256k1 has no
    // Bulletproof module. Do not invent those verifiers; fail closed.
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
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto const destination = ctx_.tx[sfDestination];
    auto const sleDst = view().read(keylet::account(destination));
    if (auto const err = verifyDepositPreauth(
            ctx_.tx, view(), accountID_, destination, sleDst, ctx_.journal);
        !isTesSuccess(err))
        return err;

    auto issuance = view().peek(keylet::mptIssuance(id));
    auto sender = view().peek(keylet::mptoken(id, accountID_));
    auto receiver = view().peek(keylet::mptoken(id, destination));
    if (!issuance || !sender || !receiver)
        return tefINTERNAL;

    auto const spending = confidential_mpt::subtractCiphertexts(
        makeSlice(sender->getFieldVL(sfConfidentialBalanceSpending)),
        ctx_.tx[sfSenderEncryptedAmount]);
    auto const senderIssuer = confidential_mpt::subtractCiphertexts(
        makeSlice(sender->getFieldVL(sfIssuerEncryptedBalance)),
        ctx_.tx[sfIssuerEncryptedAmount]);
    auto const inbox = confidential_mpt::addCiphertexts(
        makeSlice(receiver->getFieldVL(sfConfidentialBalanceInbox)),
        ctx_.tx[sfDestinationEncryptedAmount]);
    auto const receiverIssuer = confidential_mpt::addCiphertexts(
        makeSlice(receiver->getFieldVL(sfIssuerEncryptedBalance)),
        ctx_.tx[sfIssuerEncryptedAmount]);
    if (!spending || !senderIssuer || !inbox || !receiverIssuer)
        return tefINTERNAL;

    sender->setFieldVL(sfConfidentialBalanceSpending, *spending);
    sender->setFieldVL(sfIssuerEncryptedBalance, *senderIssuer);
    sender->setFieldU32(
        sfConfidentialBalanceVersion,
        sender->at(sfConfidentialBalanceVersion) + 1u);
    receiver->setFieldVL(sfConfidentialBalanceInbox, *inbox);
    receiver->setFieldVL(sfIssuerEncryptedBalance, *receiverIssuer);

    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const senderAuditor = confidential_mpt::subtractCiphertexts(
            makeSlice(sender->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        auto const receiverAuditor = confidential_mpt::addCiphertexts(
            makeSlice(receiver->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        if (!senderAuditor || !receiverAuditor)
            return tefINTERNAL;
        sender->setFieldVL(sfAuditorEncryptedBalance, *senderAuditor);
        receiver->setFieldVL(sfAuditorEncryptedBalance, *receiverAuditor);
    }

    view().update(sender);
    view().update(receiver);
    return tesSUCCESS;
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
