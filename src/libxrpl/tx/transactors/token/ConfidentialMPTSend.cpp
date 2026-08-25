#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <utility/mpt_utility.h>

#include <algorithm>
#include <array>

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

    std::array<mpt_confidential_participant, 4> participants{};
    auto setParticipant = [&](std::size_t index, Slice key, Slice ciphertext) {
        if (key.size() != kMPT_PUBKEY_SIZE ||
            ciphertext.size() != kMPT_ELGAMAL_TOTAL_SIZE)
            return false;
        std::copy(key.begin(), key.end(), participants[index].pubkey);
        std::copy(
            ciphertext.begin(),
            ciphertext.end(),
            participants[index].ciphertext);
        return true;
    };
    if (!setParticipant(
            0,
            makeSlice(sender->getFieldVL(sfHolderEncryptionKey)),
            ctx.tx[sfSenderEncryptedAmount]) ||
        !setParticipant(
            1,
            makeSlice(receiver->getFieldVL(sfHolderEncryptionKey)),
            ctx.tx[sfDestinationEncryptedAmount]) ||
        !setParticipant(
            2,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey)),
            ctx.tx[sfIssuerEncryptedAmount]) ||
        (auditorRequired &&
         !setParticipant(
             3,
             makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)),
             ctx.tx[sfAuditorEncryptedAmount])))
        return tecBAD_PROOF;

    auto const context = confidential_mpt::proofContext(
        ctx.tx,
        destination,
        sender->at(sfConfidentialBalanceVersion));
    auto const proof = ctx.tx.getFieldVL(sfZKProof);
    auto const senderBalance =
        sender->getFieldVL(sfConfidentialBalanceSpending);
    auto const amountCommitment = ctx.tx.getFieldVL(sfAmountCommitment);
    auto const balanceCommitment = ctx.tx.getFieldVL(sfBalanceCommitment);
    if (context.size() != kMPT_HALF_SHA_SIZE ||
        mpt_verify_send_proof(
            proof.data(),
            participants.data(),
            auditorRequired ? 4 : 3,
            senderBalance.data(),
            amountCommitment.data(),
            balanceCommitment.data(),
            context.data()) != 0)
        return tecBAD_PROOF;

    Scalar challenge;
    if (!parseNonZeroScalar(
            Slice(proof.data(), kScalarBytes), challenge))
        return tecBAD_PROOF;
    auto creditAndRerandomize = [&](SField const& balanceField,
                                    SField const& amountField,
                                    Slice key) {
        auto credited = confidential_mpt::addCiphertexts(
            makeSlice(receiver->getFieldVL(balanceField)),
            makeSlice(ctx.tx.getFieldVL(amountField)));
        CompressedPoint publicKey;
        Ciphertext zero;
        CiphertextBlob zeroBlob;
        if (!credited || !parseCompressedPoint(key, publicKey) ||
            !encrypt(publicKey, 0, challenge, zero) ||
            !serializeCiphertext(zero, zeroBlob))
            return false;
        return confidential_mpt::addCiphertexts(
                   makeSlice(*credited), makeSlice(zeroBlob))
            .has_value();
    };
    if (!creditAndRerandomize(
            sfConfidentialBalanceInbox,
            sfDestinationEncryptedAmount,
            makeSlice(receiver->getFieldVL(sfHolderEncryptionKey))) ||
        !creditAndRerandomize(
            sfIssuerEncryptedBalance,
            sfIssuerEncryptedAmount,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey))) ||
        (auditorRequired &&
         !creditAndRerandomize(
             sfAuditorEncryptedBalance,
             sfAuditorEncryptedAmount,
             makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)))))
        return tecBAD_PROOF;
    return tesSUCCESS;
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
