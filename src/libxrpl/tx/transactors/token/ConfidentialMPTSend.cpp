#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/crypto/confidential/Proofs.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <algorithm>

namespace xrpl {

using namespace crypto::confidential;

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

    Ciphertext senderAmount;
    Ciphertext destinationAmount;
    Ciphertext issuerAmount;
    Ciphertext senderBalance;
    CompressedPoint senderKey;
    CompressedPoint destinationKey;
    CompressedPoint issuerKey;
    CompressedPoint amountCommitment;
    CompressedPoint balanceCommitment;
    if (!parseCiphertext(
            makeSlice(ctx.tx.getFieldVL(sfSenderEncryptedAmount)),
            senderAmount) ||
        !parseCiphertext(
            makeSlice(ctx.tx.getFieldVL(sfDestinationEncryptedAmount)),
            destinationAmount) ||
        !parseCiphertext(
            makeSlice(ctx.tx.getFieldVL(sfIssuerEncryptedAmount)),
            issuerAmount) ||
        !parseCiphertext(
            makeSlice(sender->getFieldVL(sfConfidentialBalanceSpending)),
            senderBalance) ||
        !parseCompressedPoint(
            makeSlice(sender->getFieldVL(sfHolderEncryptionKey)), senderKey) ||
        !parseCompressedPoint(
            makeSlice(receiver->getFieldVL(sfHolderEncryptionKey)),
            destinationKey) ||
        !parseCompressedPoint(
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey)), issuerKey) ||
        !parseCompressedPoint(ctx.tx[sfAmountCommitment], amountCommitment) ||
        !parseCompressedPoint(ctx.tx[sfBalanceCommitment], balanceCommitment))
        return tecBAD_PROOF;

    SendSigmaStatement statement{
        .recipientPublicKeys = {senderKey, destinationKey, issuerKey},
        .senderPublicKey = senderKey,
        .sharedCiphertext = senderAmount.R,
        .encryptedAmounts = {
            senderAmount.S, destinationAmount.S, issuerAmount.S},
        .amountCommitment = amountCommitment,
        .balanceCommitment = balanceCommitment,
        .balanceCiphertext = senderBalance};
    if (senderAmount.R != destinationAmount.R ||
        senderAmount.R != issuerAmount.R)
        return tecBAD_PROOF;

    if (auditorRequired)
    {
        Ciphertext auditorAmount;
        CompressedPoint auditorKey;
        if (!parseCiphertext(
                makeSlice(ctx.tx.getFieldVL(sfAuditorEncryptedAmount)),
                auditorAmount) ||
            !parseCompressedPoint(
                makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)),
                auditorKey) ||
            auditorAmount.R != senderAmount.R)
            return tecBAD_PROOF;
        statement.recipientPublicKeys.push_back(auditorKey);
        statement.encryptedAmounts.push_back(auditorAmount.S);
    }

    SendSigmaProof sigma;
    auto const proof = ctx.tx.getFieldVL(sfZKProof);
    std::copy_n(proof.begin(), sigma.size(), sigma.begin());
    auto const context = confidential_mpt::proofContext(
        ctx.tx,
        destination,
        sender->at(sfConfidentialBalanceVersion));
    if (!verifySendSigmaProof(
            statement, sigma, makeSlice(context)))
        return tecBAD_PROOF;

    // The updated document fully specifies the compact sigma proof above, but
    // still only cites standard Bulletproofs without fixing generator
    // derivation or serialization. Its required 754-byte encoding is
    // incompatible with the maintained secp256k1-zkp encoding, so the range
    // proof remains fail-closed rather than accepting an invented transcript.
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
    auto inbox = confidential_mpt::addCiphertexts(
        makeSlice(receiver->getFieldVL(sfConfidentialBalanceInbox)),
        ctx_.tx[sfDestinationEncryptedAmount]);
    auto receiverIssuer = confidential_mpt::addCiphertexts(
        makeSlice(receiver->getFieldVL(sfIssuerEncryptedBalance)),
        ctx_.tx[sfIssuerEncryptedAmount]);
    if (!spending || !senderIssuer || !inbox || !receiverIssuer)
        return tefINTERNAL;

    sender->setFieldVL(sfConfidentialBalanceSpending, *spending);
    sender->setFieldVL(sfIssuerEncryptedBalance, *senderIssuer);
    sender->setFieldU32(
        sfConfidentialBalanceVersion,
        sender->at(sfConfidentialBalanceVersion) + 1u);
    Scalar challenge;
    auto const proof = ctx_.tx.getFieldVL(sfZKProof);
    if (!parseNonZeroScalar(
            Slice(proof.data(), kScalarBytes), challenge))
        return tefINTERNAL;
    auto rerandomize = [&](std::optional<Blob>& ciphertext, Slice key) {
        CompressedPoint publicKey;
        Ciphertext zero;
        CiphertextBlob zeroBlob;
        if (!ciphertext || !parseCompressedPoint(key, publicKey) ||
            !encrypt(publicKey, 0, challenge, zero) ||
            !serializeCiphertext(zero, zeroBlob))
            return false;
        ciphertext = confidential_mpt::addCiphertexts(
            makeSlice(*ciphertext), makeSlice(zeroBlob));
        return ciphertext.has_value();
    };
    if (!rerandomize(
            inbox, makeSlice(receiver->getFieldVL(sfHolderEncryptionKey))) ||
        !rerandomize(
            receiverIssuer,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey))))
        return tefINTERNAL;
    receiver->setFieldVL(sfConfidentialBalanceInbox, *inbox);
    receiver->setFieldVL(sfIssuerEncryptedBalance, *receiverIssuer);

    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const senderAuditor = confidential_mpt::subtractCiphertexts(
            makeSlice(sender->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        auto receiverAuditor = confidential_mpt::addCiphertexts(
            makeSlice(receiver->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        if (!senderAuditor || !receiverAuditor)
            return tefINTERNAL;
        if (!rerandomize(
                receiverAuditor,
                makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey))))
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
