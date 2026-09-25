#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Bulletproof.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/ConfidentialProofs.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTHelpers.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace xrpl {

using namespace confidential;
namespace cm = confidential_mpt;

namespace {

// Updated spec section 3.11: pi_send (192 bytes) || aggregated Bulletproof
// over (PC_m, PC_rem) (754 bytes).
constexpr std::size_t kProofLength = kSendSigmaProofLength + kAggregatedRangeProofLength;

// Ciphertext fields in recipient order P_1..P_n (resolution 16).
constexpr std::array<SF_VL const*, 4> kAmountFields{
    &sfSenderEncryptedAmount,
    &sfDestinationEncryptedAmount,
    &sfIssuerEncryptedAmount,
    &sfAuditorEncryptedAmount};

}  // namespace

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cm::baseFee(view, tx);
}

bool
ConfidentialMPTSend::checkExtraFeatures(PreflightContext const& ctx)
{
    return !ctx.tx.isFieldPresent(sfCredentialIDs) || ctx.rules.enabled(featureCredentials);
}

NotTEC
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    auto const& tx = ctx.tx;

    // XLS-0096 section 8.3.1(2)-(3); section A.10 also rules out the issuer
    // as a destination, since it cannot hold confidential balances.
    auto const issuer = MPTIssue{tx[sfMPTokenIssuanceID]}.getIssuer();
    if (issuer == tx[sfAccount] || issuer == tx[sfDestination] ||
        tx[sfAccount] == tx[sfDestination])
        return temMALFORMED;

    if (tx.getFieldVL(sfZKProof).size() != kProofLength || !cm::point(tx, sfBalanceCommitment) ||
        !cm::point(tx, sfAmountCommitment))
        return temMALFORMED;

    if (auto const ter = cm::checkCiphertexts(
            tx,
            {&sfSenderEncryptedAmount,
             &sfDestinationEncryptedAmount,
             &sfIssuerEncryptedAmount,
             &sfAuditorEncryptedAmount});
        !isTesSuccess(ter))
        return ter;

    // The relation (eq. 19) has one C1 = r·G shared by every recipient
    // (resolution 17).
    auto const c1 = cm::ciphertext(tx, *kAmountFields.front())->c1;
    for (auto const* field : std::span(kAmountFields).subspan(1))
    {
        if (tx.isFieldPresent(*field) && cm::ciphertext(tx, *field)->c1 != c1)
            return temBAD_CIPHERTEXT;
    }

    if (auto const err = credentials::checkFields(tx, ctx.j); !isTesSuccess(err))
        return err;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const account = tx[sfAccount];
    auto const destination = tx[sfDestination];
    auto const id = tx[sfMPTokenIssuanceID];

    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    if (!issuance)
        return tecOBJECT_NOT_FOUND;

    // XLS-0096 section 8.3.2, in order.
    auto const sleDst = ctx.view.read(keylet::account(destination));
    if (!sleDst)
        return tecNO_TARGET;
    // XLS-0096 section 8.2 has no DestinationTag, but every other transfer to
    // an account that requires one fails without it, and so does a Send.
    if (sleDst->isFlag(lsfRequireDestTag) && !tx.isFieldPresent(sfDestinationTag))
        return tecDST_TAG_NEEDED;
    if (!issuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    auto const keys = cm::issuanceKeys(*issuance);
    auto const sender = ctx.view.read(keylet::mptoken(id, account));
    auto const receiver = ctx.view.read(keylet::mptoken(id, destination));
    if (!keys || !sender || !receiver || !cm::isInitialized(*sender) ||
        !cm::isInitialized(*receiver))
        return tecNO_PERMISSION;

    if (auto const ter = cm::checkAuditorPolicy(tx, *keys); !isTesSuccess(ter))
        return ter;

    MPTIssue const mptIssue{id};
    for (auto const& party : {account, destination})
    {
        if (auto const ter = requireAuth(ctx.view, mptIssue, party); !isTesSuccess(ter))
            return ter;
    }

    // Before any proof, so a frozen party's retries cost nothing.
    if (isFrozen(ctx.view, account, mptIssue) || isFrozen(ctx.view, destination, mptIssue))
        return terFROZEN;

    if (auto const err = credentials::valid(tx, ctx.view, account, ctx.j); !isTesSuccess(err))
        return err;

    // Section 8.3.2.1: deposit authorization is decided here, before any
    // proof and without removing expired credentials; doApply removes those
    // (tecEXPIRED) only once authorization has passed.
    if (sleDst->isFlag(lsfDepositAuth) &&
        !ctx.view.exists(keylet::depositPreauth(destination, account)))
    {
        if (!tx.isFieldPresent(sfCredentialIDs))
            return tecNO_PERMISSION;
        if (auto const err = credentials::authorizedDepositPreauth(
                ctx.view, tx.getFieldV256(sfCredentialIDs), destination);
            !isTesSuccess(err))
            return err;
    }

    auto const senderKey = cm::point(*sender, sfHolderEncryptionKey);
    auto const receiverKey = cm::point(*receiver, sfHolderEncryptionKey);
    auto const spending = cm::ciphertext(*sender, sfConfidentialBalanceSpending);
    if (!senderKey || !receiverKey || !spending)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // Updated spec sections 3.4-3.7: one sigma proof over every recipient,
    // PC_m and PC_b, and a Bulletproof that PC_m and PC_b - PC_m open to
    // values in [0, 2^64), both bound to the destination and the sender's
    // spending balance version.
    SendStatement statement{
        .recipientKeys = {*senderKey, *receiverKey, keys->issuer},
        .senderKey = *senderKey,
        .c1 = cm::ciphertext(tx, sfSenderEncryptedAmount)->c1,
        .c2 = {},
        .amountCommitment = *cm::point(tx, sfAmountCommitment),
        .balanceCommitment = *cm::point(tx, sfBalanceCommitment),
        .balance = *spending};
    if (keys->auditor)
        statement.recipientKeys.push_back(*keys->auditor);
    for (auto const* field : kAmountFields)
    {
        if (tx.isFieldPresent(*field))
            statement.c2.push_back(cm::ciphertext(tx, *field)->c2);
    }

    auto const contextID =
        cm::contextID(tx, destination, sender->getFieldU32(sfConfidentialBalanceVersion));
    Blob const proof = tx.getFieldVL(sfZKProof);
    Slice const sigma(proof.data(), kSendSigmaProofLength);
    Slice const range(proof.data() + kSendSigmaProofLength, kAggregatedRangeProofLength);
    if (!verifySend(statement, sigma, contextID))
        return tecBAD_PROOF;
    std::array<Point, 2> const commitments{
        statement.amountCommitment, statement.balanceCommitment - statement.amountCommitment};
    if (!verifyRange(commitments, range, contextID))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::doApply()
{
    auto const& tx = ctx_.tx;
    auto const id = tx[sfMPTokenIssuanceID];
    auto const destination = tx[sfDestination];

    // Section 8.3.2.1: removes expired credentials (tecEXPIRED); preclaim
    // already decided deposit authorization.
    if (auto const err = verifyDepositPreauth(
            tx, view(), accountID_, destination, view().read(keylet::account(destination)), j_);
        !isTesSuccess(err))
        return err;

    auto const issuance = view().read(keylet::mptIssuance(id));
    auto sender = view().peek(keylet::mptoken(id, accountID_));
    auto receiver = view().peek(keylet::mptoken(id, destination));
    if (!issuance || !sender || !receiver)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    auto const keys = cm::issuanceKeys(*issuance);
    auto const receiverKey = cm::point(*receiver, sfHolderEncryptionKey);
    auto const e = cm::sendChallenge(tx);
    if (!keys || !receiverKey || !e)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const amount = [&](SF_VL const& field) { return *cm::ciphertext(tx, field); };

    // Updated spec eq. (8)-(10): debit the sender and advance its version.
    if (auto const ter =
            cm::debit(*sender, sfConfidentialBalanceSpending, amount(sfSenderEncryptedAmount));
        !isTesSuccess(ter))
        return ter;
    if (auto const ter =
            cm::debit(*sender, sfIssuerEncryptedBalance, amount(sfIssuerEncryptedAmount));
        !isTesSuccess(ter))
        return ter;
    cm::advanceVersion(*sender);

    // Eq. (11)-(13): credit the receiver, re-randomized with Enc(0; e). The
    // challenge e hashes C1 and every C2, so no sender can steer the sum to
    // the identity (except with negligible probability).
    auto const zero = Scalar{};
    if (auto const ter = cm::credit(
            *receiver,
            sfConfidentialBalanceInbox,
            amount(sfDestinationEncryptedAmount) + elGamalEncrypt(zero, *e, *receiverKey));
        !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE
    if (auto const ter = cm::credit(
            *receiver,
            sfIssuerEncryptedBalance,
            amount(sfIssuerEncryptedAmount) + elGamalEncrypt(zero, *e, keys->issuer));
        !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE

    // Resolutions 19-20: both auditor mirrors follow the issuer mirrors.
    if (keys->auditor)
    {
        if (auto const ter =
                cm::debit(*sender, sfAuditorEncryptedBalance, amount(sfAuditorEncryptedAmount));
            !isTesSuccess(ter))
            return ter;
        if (auto const ter = cm::credit(
                *receiver,
                sfAuditorEncryptedBalance,
                amount(sfAuditorEncryptedAmount) + elGamalEncrypt(zero, *e, *keys->auditor));
            !isTesSuccess(ter))
            return ter;  // LCOV_EXCL_LINE
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
    // ValidConfidentialMPToken checks this transaction's state changes.
}

bool
ConfidentialMPTSend::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // ValidConfidentialMPToken checks this transaction's state changes.
    return true;
}

}  // namespace xrpl
