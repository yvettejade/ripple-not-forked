#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/ledger/helpers/TokenHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/tx/ApplyContext.h>
#include <xrpl/tx/Transactor.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace xrpl {
namespace {

using confidential_mpt::Ciphertext;
using confidential_mpt::Point;
using confidential_mpt::Scalar;
using confidential_mpt::SendPublicInput;
using confidential_mpt::SendVerifyResult;

[[nodiscard]] std::optional<Point>
readPoint(Slice data) noexcept
{
    if (!confidential_mpt::isValidCompressedPoint(data))
        return std::nullopt;
    Point p{};
    std::memcpy(p.data(), data.data(), confidential_mpt::kPointBytes);
    return p;
}

[[nodiscard]] Blob
toBlob(Ciphertext const& ct)
{
    return Blob(ct.begin(), ct.end());
}

[[nodiscard]] Slice
toSlice(uint256 const& h)
{
    return Slice{h.data(), h.size()};
}

/** TransactionContextID for Send sigma binding (Updated_ConfidentialMPT §3.7). */
[[nodiscard]] uint256
makeSendTransactionContext(STTx const& tx, std::uint32_t cbsVersion)
{
    return sha512Half(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
        tx.getAccountID(sfAccount),
        tx[sfMPTokenIssuanceID],
        tx.getSeqProxy().value(),
        tx.getAccountID(sfDestination),
        cbsVersion);
}

/**
 * Aggregated Bulletproof over PC_m and PC_rem = PC_b - PC_m (754 bytes).
 * Context is the same TransactionContextID used for the compact sigma proof.
 *
 * SPEC INCONSISTENCY (xls-0096 §5.4 / payload notes): the Bulletproof covers
 * [0, 2^64) while the text says transactors independently reject amounts above
 * maxMPTokenAmount (2^63-1). For ConfidentialMPTSend the amount is hidden, so
 * an independent plaintext cap check is impossible without opening the
 * commitment or shrinking the range proof to 63 bits (which would change the
 * normative 754-byte aggregated layout). Convert / ConvertBack / Clawback
 * enforce kMaxMPTokenAmount on their public MPTAmount fields. Until the specs
 * pick either a 63-bit range proof or drop the "independent reject" language
 * for Send, verification follows the stated 64-bit / 754-byte proof.
 */
[[nodiscard]] bool
verifySendAggregatedBulletproof(
    Point const& amountCommitment,
    Point const& balanceCommitment,
    Slice rangeProof,
    Slice context) noexcept
{
    if (rangeProof.size() != ConfidentialMPTSend::kAggregatedBulletproofBytes)
        return false;
    auto const rem = confidential_mpt::pointSub(balanceCommitment, amountCommitment);
    if (!rem)
        return false;
    return confidential_mpt::verifyAggregatedBulletproof(
        amountCommitment, *rem, rangeProof, context);
}

struct ParsedSendCrypto
{
    Ciphertext senderAmount{};
    Ciphertext destinationAmount{};
    Ciphertext issuerAmount{};
    std::optional<Ciphertext> auditorAmount;
    Point amountCommitment{};
    Point balanceCommitment{};
    Slice sigmaProof;
    Slice rangeProof;
};

[[nodiscard]] std::optional<ParsedSendCrypto>
parseSendCryptoFields(STTx const& tx, bool auditorRequired) noexcept
{
    auto const senderCt = confidential_mpt::parseCiphertext(tx[sfSenderEncryptedAmount]);
    auto const destCt = confidential_mpt::parseCiphertext(tx[sfDestinationEncryptedAmount]);
    auto const issuerCt = confidential_mpt::parseCiphertext(tx[sfIssuerEncryptedAmount]);
    if (!senderCt || !destCt || !issuerCt)
        return std::nullopt;

    // Shared-randomness: all transfer ciphertexts must share C1.
    auto const c1 = confidential_mpt::ciphertextC1(*senderCt);
    if (confidential_mpt::ciphertextC1(*destCt) != c1 ||
        confidential_mpt::ciphertextC1(*issuerCt) != c1)
        return std::nullopt;

    std::optional<Ciphertext> auditorCt;
    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auditorCt = confidential_mpt::parseCiphertext(tx[sfAuditorEncryptedAmount]);
        if (!auditorCt)
            return std::nullopt;
        if (confidential_mpt::ciphertextC1(*auditorCt) != c1)
            return std::nullopt;
    }
    else if (auditorRequired)
    {
        return std::nullopt;
    }

    auto const amountCm = readPoint(tx[sfAmountCommitment]);
    auto const balanceCm = readPoint(tx[sfBalanceCommitment]);
    if (!amountCm || !balanceCm)
        return std::nullopt;

    auto const split = confidential_mpt::splitSendProof(tx[sfZKProof]);
    if (!split)
        return std::nullopt;

    ParsedSendCrypto out;
    out.senderAmount = *senderCt;
    out.destinationAmount = *destCt;
    out.issuerAmount = *issuerCt;
    out.auditorAmount = auditorCt;
    out.amountCommitment = *amountCm;
    out.balanceCommitment = *balanceCm;
    out.sigmaProof = split->sigma;
    out.rangeProof = split->rangeProof;
    return out;
}


/** Updated_ConfidentialMPT §3.8: after proof verify, simulate inbox credit +
 *  Fiat–Shamir re-randomization and reject if any resulting ciphertext is not
 *  a well-formed secp256k1 element (point at infinity / add failure).
 */
[[nodiscard]] bool
receiverRerandomizationWellFormed(
    SLE const& sleDestMpt,
    SLE const& sleIssuance,
    ParsedSendCrypto const& parsed,
    Scalar const& e,
    bool hasAuditorKey,
    std::optional<Point> const& auditorPk) noexcept
{
    auto const destPk = readPoint(sleDestMpt[sfHolderEncryptionKey]);
    auto const issuerPk = readPoint(sleIssuance[sfIssuerEncryptionKey]);
    if (!destPk || !issuerPk)
        return false;

    auto const inbox =
        confidential_mpt::parseCiphertext(sleDestMpt[sfConfidentialBalanceInbox]);
    auto const issuerBal =
        confidential_mpt::parseCiphertext(sleDestMpt[sfIssuerEncryptedBalance]);
    if (!inbox || !issuerBal)
        return false;

    auto const creditedInbox =
        confidential_mpt::ciphertextAdd(*inbox, parsed.destinationAmount);
    if (!creditedInbox)
        return false;
    if (!confidential_mpt::rerandomizeWithScalar(*creditedInbox, *destPk, e))
        return false;

    auto const creditedIssuer =
        confidential_mpt::ciphertextAdd(*issuerBal, parsed.issuerAmount);
    if (!creditedIssuer)
        return false;
    if (!confidential_mpt::rerandomizeWithScalar(*creditedIssuer, *issuerPk, e))
        return false;

    if (hasAuditorKey)
    {
        auto const auditorBal =
            confidential_mpt::parseCiphertext(sleDestMpt[sfAuditorEncryptedBalance]);
        if (!auditorBal || !parsed.auditorAmount || !auditorPk)
            return false;
        auto const creditedAuditor =
            confidential_mpt::ciphertextAdd(*auditorBal, *parsed.auditorAmount);
        if (!creditedAuditor)
            return false;
        if (!confidential_mpt::rerandomizeWithScalar(*creditedAuditor, *auditorPk, e))
            return false;
    }
    return true;
}

[[nodiscard]] bool
hasInitializedConfidentialState(SLE const& mpt)
{
    return mpt.isFieldPresent(sfHolderEncryptionKey) &&
        mpt.isFieldPresent(sfConfidentialBalanceSpending) &&
        mpt.isFieldPresent(sfConfidentialBalanceInbox) &&
        mpt.isFieldPresent(sfIssuerEncryptedBalance) &&
        mpt.isFieldPresent(sfConfidentialBalanceVersion);
}

[[nodiscard]] SendVerifyResult
verifySendProofsWithDestKey(
    STTx const& tx,
    SLE const& sleSenderMpt,
    SLE const& sleDestMpt,
    SLE const& sleIssuance,
    ParsedSendCrypto const& crypto,
    std::optional<Point> const& auditorPk,
    beast::Journal j)
{
    SendVerifyResult fail{};
    fail.ok = false;

    auto const senderPk = readPoint(sleSenderMpt[sfHolderEncryptionKey]);
    auto const destPk = readPoint(sleDestMpt[sfHolderEncryptionKey]);
    auto const issuerPk = readPoint(sleIssuance[sfIssuerEncryptionKey]);
    if (!senderPk || !destPk || !issuerPk)
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: invalid holder/issuer encryption keys";
        return fail;
    }

    if (auditorPk && !crypto.auditorAmount)
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: missing auditor ciphertext";
        return fail;
    }
    if (!auditorPk && crypto.auditorAmount)
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: unexpected auditor ciphertext";
        return fail;
    }

    auto const spending =
        confidential_mpt::parseCiphertext(sleSenderMpt[sfConfidentialBalanceSpending]);
    if (!spending)
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: invalid spending balance ciphertext";
        return fail;
    }

    SendPublicInput x;
    x.recipientKeys.push_back(*senderPk);
    x.recipientKeys.push_back(*destPk);
    x.recipientKeys.push_back(*issuerPk);
    if (auditorPk)
        x.recipientKeys.push_back(*auditorPk);

    x.senderKey = *senderPk;
    x.c1 = confidential_mpt::ciphertextC1(crypto.senderAmount);
    x.c2.push_back(confidential_mpt::ciphertextC2(crypto.senderAmount));
    x.c2.push_back(confidential_mpt::ciphertextC2(crypto.destinationAmount));
    x.c2.push_back(confidential_mpt::ciphertextC2(crypto.issuerAmount));
    if (crypto.auditorAmount)
        x.c2.push_back(confidential_mpt::ciphertextC2(*crypto.auditorAmount));

    x.amountCommitment = crypto.amountCommitment;
    x.balanceCommitment = crypto.balanceCommitment;
    x.balanceC1 = confidential_mpt::ciphertextC1(*spending);
    x.balanceC2 = confidential_mpt::ciphertextC2(*spending);

    auto const cbsVersion = sleSenderMpt.getFieldU32(sfConfidentialBalanceVersion);
    auto const context = makeSendTransactionContext(tx, cbsVersion);
    auto const sigma = confidential_mpt::verifySendSigma(x, crypto.sigmaProof, toSlice(context));
    if (!sigma.ok)
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: compact send sigma verification failed";
        return sigma;
    }

    if (!verifySendAggregatedBulletproof(
            crypto.amountCommitment, crypto.balanceCommitment, crypto.rangeProof, toSlice(context)))
    {
        JLOG(j.trace()) << "ConfidentialMPTSend: aggregated Bulletproof verification failed";
        fail.ok = false;
        return fail;
    }

    return sigma;
}

}  // namespace

//------------------------------------------------------------------------------

bool
ConfidentialMPTSend::checkExtraFeatures(PreflightContext const& ctx)
{
    return !ctx.tx.isFieldPresent(sfCredentialIDs) || ctx.rules.enabled(featureCredentials);
}

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    // XLS-0096 §9: confidential MPT transactions charge 10x the normal base fee.
    return Transactor::calculateBaseFee(view, tx) * 10;
}

NotTEC
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    if (auto const err = credentials::checkFields(ctx.tx, ctx.j); !isTesSuccess(err))
        return err;

    auto const& tx = ctx.tx;
    auto const account = tx.getAccountID(sfAccount);
    auto const destination = tx.getAccountID(sfDestination);

    if (!destination)
        return temMALFORMED;

    if (account == destination)
        return temMALFORMED;

    // Commitment points: exactly 33-byte valid compressed points.
    if (!confidential_mpt::isValidCompressedPoint(tx[sfBalanceCommitment]) ||
        !confidential_mpt::isValidCompressedPoint(tx[sfAmountCommitment]))
        return temMALFORMED;

    // ZKProof must be exactly 946 bytes (192 sigma + 754 Bulletproof).
    if (tx[sfZKProof].size() != kZKProofBytes)
        return temMALFORMED;

    auto const split = confidential_mpt::splitSendProof(tx[sfZKProof]);
    if (!split || split->sigma.size() != kSendSigmaProofBytes ||
        split->rangeProof.size() != kAggregatedBulletproofBytes)
        return temMALFORMED;

    // Ciphertexts: required fields must parse as valid 66-byte ElGamal.
    if (!confidential_mpt::parseCiphertext(tx[sfSenderEncryptedAmount]) ||
        !confidential_mpt::parseCiphertext(tx[sfDestinationEncryptedAmount]) ||
        !confidential_mpt::parseCiphertext(tx[sfIssuerEncryptedAmount]))
        return temBAD_CIPHERTEXT;

    if (tx.isFieldPresent(sfAuditorEncryptedAmount) &&
        !confidential_mpt::parseCiphertext(tx[sfAuditorEncryptedAmount]))
        return temBAD_CIPHERTEXT;

    // Shared C1 across all amount ciphertexts (same encryption randomness).
    auto const senderCt = *confidential_mpt::parseCiphertext(tx[sfSenderEncryptedAmount]);
    auto const c1 = confidential_mpt::ciphertextC1(senderCt);
    auto const destCt = *confidential_mpt::parseCiphertext(tx[sfDestinationEncryptedAmount]);
    auto const issuerCt = *confidential_mpt::parseCiphertext(tx[sfIssuerEncryptedAmount]);
    if (confidential_mpt::ciphertextC1(destCt) != c1 ||
        confidential_mpt::ciphertextC1(issuerCt) != c1)
        return temBAD_CIPHERTEXT;

    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auto const auditorCt = *confidential_mpt::parseCiphertext(tx[sfAuditorEncryptedAmount]);
        if (confidential_mpt::ciphertextC1(auditorCt) != c1)
            return temBAD_CIPHERTEXT;
    }

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const account = tx.getAccountID(sfAccount);
    auto const destination = tx.getAccountID(sfDestination);
    auto const mptIssuanceID = tx[sfMPTokenIssuanceID];

    auto const sleDstAccount = ctx.view.read(keylet::account(destination));
    if (!sleDstAccount)
        return tecNO_TARGET;

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptIssuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    auto const issuer = (*sleIssuance)[sfIssuer];

    // Sender must not be the issuance issuer (dedicated holder accounts are OK).
    if (account == issuer)
        return temMALFORMED;

    if (!sleIssuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    // TransferFee is incompatible with confidential transfers.
    // Create/IssuanceSet already refuse a non-zero fee on a confidential
    // issuance (temBAD_TRANSFER_FEE / tecNO_PERMISSION), so this branch is
    // defense in depth for a ledger state that valid transactions cannot
    // currently produce.
    if ((*sleIssuance)[sfTransferFee] != 0)
        return tecNO_PERMISSION;

    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey) ||
        !confidential_mpt::isValidCompressedPoint((*sleIssuance)[sfIssuerEncryptionKey]))
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (hasAuditorKey)
    {
        if (!confidential_mpt::isValidCompressedPoint((*sleIssuance)[sfAuditorEncryptionKey]))
            return tecNO_PERMISSION;
        if (!tx.isFieldPresent(sfAuditorEncryptedAmount))
            return tecNO_PERMISSION;
    }
    else if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        return tecNO_PERMISSION;
    }

    // Destination must not be the issuer either (issuer cannot hold confidential balances).
    if (destination == issuer)
        return tecNO_PERMISSION;

    auto const sleSenderMpt = ctx.view.read(keylet::mptoken(mptIssuanceID, account));
    auto const sleDestMpt = ctx.view.read(keylet::mptoken(mptIssuanceID, destination));
    if (!sleSenderMpt || !sleDestMpt)
        return tecOBJECT_NOT_FOUND;

    if (!hasInitializedConfidentialState(*sleSenderMpt) ||
        !hasInitializedConfidentialState(*sleDestMpt))
        return tecNO_PERMISSION;

    if (hasAuditorKey)
    {
        if (!sleSenderMpt->isFieldPresent(sfAuditorEncryptedBalance) ||
            !sleDestMpt->isFieldPresent(sfAuditorEncryptedBalance))
            return tecNO_PERMISSION;
    }

    MPTIssue const mptIssue{mptIssuanceID};

    if (auto const ter = requireAuth(ctx.view, mptIssue, account); !isTesSuccess(ter))
        return ter;
    if (auto const ter = requireAuth(ctx.view, mptIssue, destination); !isTesSuccess(ter))
        return ter;

    if (auto const ter = canTransfer(ctx.view, mptIssue, account, destination); !isTesSuccess(ter))
        return ter;

    // SPEC INCONSISTENCY (xls-0096): names terFROZEN, which is absent here.
    // checkFrozen applies the existing MPT result, tecLOCKED.
    if (auto const ter = checkFrozen(ctx.view, account, mptIssue); !isTesSuccess(ter))
        return ter;
    if (auto const ter = checkFrozen(ctx.view, destination, mptIssue); !isTesSuccess(ter))
        return ter;

    if (auto const err = credentials::valid(tx, ctx.view, account, ctx.j); !isTesSuccess(err))
        return err;

    // Deposit authorization / credential authorization against destination.
    if (sleDstAccount->isFlag(lsfDepositAuth))
    {
        if (!ctx.view.exists(keylet::depositPreauth(destination, account)))
        {
            if (!tx.isFieldPresent(sfCredentialIDs))
                return tecNO_PERMISSION;

            if (auto const ter = credentials::authorizedDepositPreauth(
                    ctx.view, tx.getFieldV256(sfCredentialIDs), destination);
                !isTesSuccess(ter))
                return ter;
        }
    }

    std::optional<Point> auditorPk;
    if (hasAuditorKey)
        auditorPk = readPoint((*sleIssuance)[sfAuditorEncryptionKey]);

    auto const parsed = parseSendCryptoFields(tx, hasAuditorKey);
    if (!parsed)
        return temBAD_CIPHERTEXT;

    auto const verified = verifySendProofsWithDestKey(
        tx, *sleSenderMpt, *sleDestMpt, *sleIssuance, *parsed, auditorPk, ctx.j);
    if (!verified.ok)
        return tecBAD_PROOF;

    // Updated_ConfidentialMPT §3.8 validation: re-randomized inbox/mirrors must
    // be well-formed before the state transition is applied.
    if (!receiverRerandomizationWellFormed(
            *sleDestMpt, *sleIssuance, *parsed, verified.challenge, hasAuditorKey, auditorPk))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = accountID_;
    auto const destination = tx.getAccountID(sfDestination);
    auto const mptIssuanceID = tx[sfMPTokenIssuanceID];

    auto const sleDstAccount = view().read(keylet::account(destination));
    if (!sleDstAccount)
        return tecNO_TARGET;

    if (auto const err =
            verifyDepositPreauth(tx, view(), account, destination, sleDstAccount, ctx_.journal);
        !isTesSuccess(err))
        return err;

    auto const sleIssuance = view().read(keylet::mptIssuance(mptIssuanceID));
    if (!sleIssuance)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    std::optional<Point> auditorPk;
    if (hasAuditorKey)
        auditorPk = readPoint((*sleIssuance)[sfAuditorEncryptionKey]);

    auto sleSenderMpt = view().peek(keylet::mptoken(mptIssuanceID, account));
    auto sleDestMpt = view().peek(keylet::mptoken(mptIssuanceID, destination));
    if (!sleSenderMpt || !sleDestMpt)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const parsed = parseSendCryptoFields(tx, hasAuditorKey);
    if (!parsed)
        return tecBAD_PROOF;  // LCOV_EXCL_LINE

    auto const verified = verifySendProofsWithDestKey(
        tx, *sleSenderMpt, *sleDestMpt, *sleIssuance, *parsed, auditorPk, ctx_.journal);
    if (!verified.ok)
        return tecBAD_PROOF;

    Scalar const& e = verified.challenge;

    auto const destPk = readPoint((*sleDestMpt)[sfHolderEncryptionKey]);
    auto const issuerPk = readPoint((*sleIssuance)[sfIssuerEncryptionKey]);
    if (!destPk || !issuerPk)
        return tecBAD_PROOF;  // LCOV_EXCL_LINE

    // --- Sender: debit spending + issuer (and auditor) mirrors; bump version ---
    {
        auto const spending =
            confidential_mpt::parseCiphertext((*sleSenderMpt)[sfConfidentialBalanceSpending]);
        auto const issuerBal =
            confidential_mpt::parseCiphertext((*sleSenderMpt)[sfIssuerEncryptedBalance]);
        if (!spending || !issuerBal)
            return tecBAD_PROOF;

        auto const newSpending = confidential_mpt::ciphertextSub(*spending, parsed->senderAmount);
        auto const newIssuerBal = confidential_mpt::ciphertextSub(*issuerBal, parsed->issuerAmount);
        if (!newSpending || !newIssuerBal)
            return tecBAD_PROOF;

        sleSenderMpt->setFieldVL(sfConfidentialBalanceSpending, toBlob(*newSpending));
        sleSenderMpt->setFieldVL(sfIssuerEncryptedBalance, toBlob(*newIssuerBal));

        if (hasAuditorKey)
        {
            auto const auditorBal =
                confidential_mpt::parseCiphertext((*sleSenderMpt)[sfAuditorEncryptedBalance]);
            if (!auditorBal || !parsed->auditorAmount)
                return tecBAD_PROOF;
            auto const newAuditorBal =
                confidential_mpt::ciphertextSub(*auditorBal, *parsed->auditorAmount);
            if (!newAuditorBal)
                return tecBAD_PROOF;
            sleSenderMpt->setFieldVL(sfAuditorEncryptedBalance, toBlob(*newAuditorBal));
        }

        auto const version = sleSenderMpt->getFieldU32(sfConfidentialBalanceVersion);
        sleSenderMpt->setFieldU32(
            sfConfidentialBalanceVersion,
            version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);
        view().update(sleSenderMpt);
    }

    // --- Receiver: credit inbox + issuer/auditor mirrors, then re-randomize with e ---
    {
        auto const inbox =
            confidential_mpt::parseCiphertext((*sleDestMpt)[sfConfidentialBalanceInbox]);
        auto const issuerBal =
            confidential_mpt::parseCiphertext((*sleDestMpt)[sfIssuerEncryptedBalance]);
        if (!inbox || !issuerBal)
            return tecBAD_PROOF;

        auto const creditedInbox =
            confidential_mpt::ciphertextAdd(*inbox, parsed->destinationAmount);
        if (!creditedInbox)
            return tecBAD_PROOF;

        auto const rerandInbox =
            confidential_mpt::rerandomizeWithScalar(*creditedInbox, *destPk, e);
        if (!rerandInbox)
        {
            // Spec §3.8: re-randomized inbox must be a well-formed group element.
            return tecBAD_PROOF;
        }

        auto const creditedIssuer =
            confidential_mpt::ciphertextAdd(*issuerBal, parsed->issuerAmount);
        if (!creditedIssuer)
            return tecBAD_PROOF;

        auto const rerandIssuer =
            confidential_mpt::rerandomizeWithScalar(*creditedIssuer, *issuerPk, e);
        if (!rerandIssuer)
            return tecBAD_PROOF;

        sleDestMpt->setFieldVL(sfConfidentialBalanceInbox, toBlob(*rerandInbox));
        sleDestMpt->setFieldVL(sfIssuerEncryptedBalance, toBlob(*rerandIssuer));

        if (hasAuditorKey)
        {
            auto const auditorBal =
                confidential_mpt::parseCiphertext((*sleDestMpt)[sfAuditorEncryptedBalance]);
            if (!auditorBal || !parsed->auditorAmount || !auditorPk)
                return tecBAD_PROOF;
            auto const creditedAuditor =
                confidential_mpt::ciphertextAdd(*auditorBal, *parsed->auditorAmount);
            if (!creditedAuditor)
                return tecBAD_PROOF;
            auto const rerandAuditor =
                confidential_mpt::rerandomizeWithScalar(*creditedAuditor, *auditorPk, e);
            if (!rerandAuditor)
                return tecBAD_PROOF;
            sleDestMpt->setFieldVL(sfAuditorEncryptedBalance, toBlob(*rerandAuditor));
        }

        view().update(sleDestMpt);
    }

    // OA and COA are intentionally unchanged (confidential redistribution only).
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
