#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/Bulletproofs.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

namespace xrpl {
namespace {

/** Compact send sigma (192) + aggregated Bulletproof (754) = 946. */
constexpr std::size_t kSendZkProofSize = kSendSigmaSize + kAggregatedBulletproofSize;

[[nodiscard]] NotTEC
checkCiphertextField(STTx const& tx, SF_VL const& field, bool required)
{
    if (!tx.isFieldPresent(field))
    {
        if (required)
            return temMALFORMED;
        return tesSUCCESS;
    }
    return validateElGamalCiphertext(tx[field]);
}

[[nodiscard]] std::optional<Secp256k1Point>
parsePk(Blob const& key)
{
    return Secp256k1Point::parse(makeSlice(key));
}

[[nodiscard]] TER
homomorphicSubtract(SLE& sle, SF_VL const& field, Slice subtraction)
{
    if (!sle.isFieldPresent(field))
        return tefINTERNAL;  // LCOV_EXCL_LINE
    auto const diff = homomorphicSubCiphertexts(makeSlice(sle.getFieldVL(field)), subtraction);
    if (!diff)
        return tefINTERNAL;
    sle.setFieldVL(field, *diff);
    return tesSUCCESS;
}

[[nodiscard]] TER
homomorphicAdd(SLE& sle, SF_VL const& field, Slice addition)
{
    if (!sle.isFieldPresent(field))
        return tefINTERNAL;  // LCOV_EXCL_LINE
    auto const sum = homomorphicAddCiphertexts(makeSlice(sle.getFieldVL(field)), addition);
    if (!sum)
        return tefINTERNAL;
    sle.setFieldVL(field, *sum);
    return tesSUCCESS;
}

/** TxSpecific := Destination || CBS_Version(sender) (uint32 BE). */
[[nodiscard]] std::array<std::uint8_t, AccountID::kBytes + 4>
sendTxSpecific(AccountID const& destination, std::uint32_t version)
{
    std::array<std::uint8_t, AccountID::kBytes + 4> out{};
    std::memcpy(out.data(), destination.data(), AccountID::kBytes);
    out[AccountID::kBytes] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    out[AccountID::kBytes + 1] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    out[AccountID::kBytes + 2] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    out[AccountID::kBytes + 3] = static_cast<std::uint8_t>(version & 0xff);
    return out;
}

[[nodiscard]] bool
sameC1(ElGamalCiphertext const& a, ElGamalCiphertext const& b)
{
    return a.c1() == b.c1();
}

/** Spec gap: Fiat–Shamir e for Enc(0;e) is the first 32 bytes of the
    transmitted compact sigma after successful verify (layout e, zm, zr, zb,
    zρ, zsk). CompactSigma does not export e separately.
*/
[[nodiscard]] std::optional<Secp256k1Scalar>
parseSigmaChallenge(Slice sigma)
{
    if (sigma.size() < Secp256k1Scalar::kSerializedSize)
        return std::nullopt;  // LCOV_EXCL_LINE
    return Secp256k1Scalar::parse(Slice(sigma.data(), Secp256k1Scalar::kSerializedSize));
}

}  // namespace

bool
ConfidentialMPTSend::checkExtraFeatures(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return false;
    // Match Payment: CredentialIDs requires featureCredentials.
    return !ctx.tx.isFieldPresent(sfCredentialIDs) || ctx.rules.enabled(featureCredentials);
}

NotTEC
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    auto const& tx = ctx.tx;

    if (auto const err = credentials::checkFields(tx, ctx.j); !isTesSuccess(err))
        return err;

    if (tx[sfAccount] == tx[sfDestination])
        return temMALFORMED;

    if (auto const r = checkCiphertextField(tx, sfSenderEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfDestinationEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfIssuerEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfAuditorEncryptedAmount, false))
        return r;

    auto const pcB = tx[sfBalanceCommitment];
    if (pcB.size() != Secp256k1Point::kSerializedSize)
        return temMALFORMED;
    if (!Secp256k1Point::parse(pcB))
        return temMALFORMED;

    auto const pcM = tx[sfAmountCommitment];
    if (pcM.size() != Secp256k1Point::kSerializedSize)
        return temMALFORMED;
    if (!Secp256k1Point::parse(pcM))
        return temMALFORMED;

    if (tx[sfZKProof].size() != kSendZkProofSize)
        return temMALFORMED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    // Spec §14: confidential send costs 10× the reference base fee.
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const sender = tx[sfAccount];
    auto const destination = tx[sfDestination];
    auto const issuanceID = tx[sfMPTokenIssuanceID];

    auto const sleDestAcct = ctx.view.read(keylet::account(destination));
    if (!sleDestAcct)
        return tecNO_TARGET;

    if (ctx.view.rules().enabled(featureCredentials))
    {
        if (auto const err = credentials::valid(tx, ctx.view, sender, ctx.j); !isTesSuccess(err))
            return err;
    }

    // Without credentials, reject DepositAuth early (AccountDelete pattern).
    // With credentials, verifyDepositPreauth in doApply handles auth + cleanup.
    if (!tx.isFieldPresent(sfCredentialIDs) && sleDestAcct->isFlag(lsfDepositAuth))
    {
        if (!ctx.view.exists(keylet::depositPreauth(destination, sender)))
            return tecNO_PERMISSION;
    }

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    // Spec §8.3.1 lists temMALFORMED for issuer-as-sender; preclaim uses
    // tecNO_PERMISSION (same pattern as Convert/Merge/ConvertBack).
    if (sender == (*sleIssuance)[sfIssuer])
        return tecNO_PERMISSION;

    // XLS-0096 § mutex: TransferFee and confidential send are incompatible.
    if ((*sleIssuance)[~sfTransferFee].value_or(0) != 0u)
        return tecNO_PERMISSION;

    auto const sleSender = ctx.view.read(keylet::mptoken(issuanceID, sender));
    if (!sleSender)
        return tecOBJECT_NOT_FOUND;

    auto const sleDest = ctx.view.read(keylet::mptoken(issuanceID, destination));
    if (!sleDest)
        return tecOBJECT_NOT_FOUND;

    // Both parties must already be confidential-initialized.
    if (!sleSender->isFieldPresent(sfHolderEncryptionKey) ||
        !sleSender->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleSender->isFieldPresent(sfIssuerEncryptedBalance))
        return tecNO_PERMISSION;

    if (!sleDest->isFieldPresent(sfHolderEncryptionKey) ||
        !sleDest->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleDest->isFieldPresent(sfIssuerEncryptedBalance))
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    bool const hasAuditorAmt = tx.isFieldPresent(sfAuditorEncryptedAmount);
    if (hasAuditorKey != hasAuditorAmt)
        return tecNO_PERMISSION;
    if (hasAuditorKey)
    {
        if (!sleSender->isFieldPresent(sfAuditorEncryptedBalance) ||
            !sleDest->isFieldPresent(sfAuditorEncryptedBalance))
            return tecNO_PERMISSION;
    }

    // Spec 8.3.2.6 names terFROZEN; MPT lock uses tecLOCKED (Merge pattern).
    if (sleSender->isFlag(lsfMPTLocked) || sleDest->isFlag(lsfMPTLocked) ||
        sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    auto const senderPk = parsePk(sleSender->getFieldVL(sfHolderEncryptionKey));
    auto const destPk = parsePk(sleDest->getFieldVL(sfHolderEncryptionKey));
    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!senderPk || !destPk || !issuerPk)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE

    auto const senderCt = parseElGamalCiphertext(tx[sfSenderEncryptedAmount]);
    auto const destCt = parseElGamalCiphertext(tx[sfDestinationEncryptedAmount]);
    auto const issuerCt = parseElGamalCiphertext(tx[sfIssuerEncryptedAmount]);
    if (!senderCt || !destCt || !issuerCt)
        return temBAD_CIPHERTEXT;  // LCOV_EXCL_LINE — preflight validated

    // CompactSigma already requires identical C1; check explicitly for clarity.
    if (!sameC1(*senderCt, *destCt) || !sameC1(*senderCt, *issuerCt))
        return tecBAD_PROOF;

    std::vector<Secp256k1Point> recipientPks;
    std::vector<ElGamalCiphertext> ciphertexts;
    recipientPks.reserve(hasAuditorAmt ? 4 : 3);
    ciphertexts.reserve(hasAuditorAmt ? 4 : 3);
    // Order: sender, dest, issuer[, auditor] — matches proveSendSigma / ciphertexts.
    recipientPks.push_back(*senderPk);
    ciphertexts.push_back(*senderCt);
    recipientPks.push_back(*destPk);
    ciphertexts.push_back(*destCt);
    recipientPks.push_back(*issuerPk);
    ciphertexts.push_back(*issuerCt);

    if (hasAuditorAmt)
    {
        auto const auditorPk = parsePk(sleIssuance->getFieldVL(sfAuditorEncryptionKey));
        if (!auditorPk)
            return tecNO_PERMISSION;  // LCOV_EXCL_LINE
        auto const auditorCt = parseElGamalCiphertext(tx[sfAuditorEncryptedAmount]);
        if (!auditorCt)
            return temBAD_CIPHERTEXT;  // LCOV_EXCL_LINE
        if (!sameC1(*senderCt, *auditorCt))
            return tecBAD_PROOF;
        recipientPks.push_back(*auditorPk);
        ciphertexts.push_back(*auditorCt);
    }

    auto const pcM = Secp256k1Point::parse(tx[sfAmountCommitment]);
    auto const pcB = Secp256k1Point::parse(tx[sfBalanceCommitment]);
    if (!pcM || !pcB)
        return temMALFORMED;  // LCOV_EXCL_LINE

    auto const balanceCt =
        parseElGamalCiphertext(makeSlice(sleSender->getFieldVL(sfConfidentialBalanceSpending)));
    if (!balanceCt)
        return tecNO_PERMISSION;

    auto const version = (*sleSender)[~sfConfidentialBalanceVersion].value_or(0);
    auto const specific = sendTxSpecific(destination, version);
    auto const ctxID = confidentialTxContextID(
        static_cast<std::uint16_t>(tx.getTxnType()),
        sender,
        issuanceID,
        tx.getSeqProxy().value(),
        makeSlice(specific));

    auto const proof = tx[sfZKProof];
    Slice const sigma(proof.data(), kSendSigmaSize);
    Slice const bp(proof.data() + kSendSigmaSize, kAggregatedBulletproofSize);

    if (!verifySendSigma(
            recipientPks, *senderPk, ciphertexts, *pcM, *pcB, *balanceCt, sigma, makeSlice(ctxID)))
        return tecBAD_PROOF;

    auto const e = parseSigmaChallenge(sigma);
    if (!e)
        return tecBAD_PROOF;  // LCOV_EXCL_LINE

    auto const pcRem = pointSubtract(*pcB, *pcM);
    if (!pcRem)
        return tecBAD_PROOF;
    if (!verifyRange64Aggregated(*pcM, *pcRem, bp))
        return tecBAD_PROOF;

    // Addendum §3.8: re-randomized inbox must not be the point at infinity.
    auto const encZeroDest = ElGamalCiphertext::encrypt(0, *destPk, *e);
    if (!encZeroDest)
        return tecBAD_PROOF;  // LCOV_EXCL_LINE
    auto const inboxPlus = destCt->add(*encZeroDest);
    if (!inboxPlus)
        return tecBAD_PROOF;
    auto const currentInbox =
        parseElGamalCiphertext(makeSlice(sleDest->getFieldVL(sfConfidentialBalanceInbox)));
    if (!currentInbox)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE
    if (!currentInbox->add(*inboxPlus))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::doApply()
{
    auto const& tx = ctx_.tx;
    auto const sender = tx[sfAccount];
    auto const destination = tx[sfDestination];
    auto const issuanceID = tx[sfMPTokenIssuanceID];

    auto const sleDestAcct = view().peek(keylet::account(destination));
    if (!sleDestAcct)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    if (auto err = verifyDepositPreauth(tx, view(), sender, destination, sleDestAcct, ctx_.journal);
        !isTesSuccess(err))
        return err;

    auto const sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto const sleSender = view().peek(keylet::mptoken(issuanceID, sender));
    auto const sleDest = view().peek(keylet::mptoken(issuanceID, destination));
    if (!sleIssuance || !sleSender || !sleDest)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const destPk = parsePk(sleDest->getFieldVL(sfHolderEncryptionKey));
    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!destPk || !issuerPk)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // Re-parse e from verified sigma (first 32 bytes).
    auto const proof = tx[sfZKProof];
    auto const e = parseSigmaChallenge(Slice(proof.data(), kSendSigmaSize));
    if (!e)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const encZeroDest = ElGamalCiphertext::encrypt(0, *destPk, *e);
    auto const encZeroIssuer = ElGamalCiphertext::encrypt(0, *issuerPk, *e);
    if (!encZeroDest || !encZeroIssuer)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // Sender: spending ⊖ SenderEncryptedAmount; issuer/auditor mirrors ⊖.
    if (auto const ter = homomorphicSubtract(
            *sleSender, sfConfidentialBalanceSpending, tx[sfSenderEncryptedAmount]))
        return ter;
    if (auto const ter =
            homomorphicSubtract(*sleSender, sfIssuerEncryptedBalance, tx[sfIssuerEncryptedAmount]))
        return ter;
    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const ter = homomorphicSubtract(
                *sleSender, sfAuditorEncryptedBalance, tx[sfAuditorEncryptedAmount]))
            return ter;
    }

    auto const version = (*sleSender)[~sfConfidentialBalanceVersion].valueOr(0);
    (*sleSender)[sfConfidentialBalanceVersion] = version + 1;

    // Receiver: inbox ⊕ DestinationEncryptedAmount ⊕ Enc(0; e).
    {
        auto const destCt = parseElGamalCiphertext(tx[sfDestinationEncryptedAmount]);
        if (!destCt)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const credited = destCt->add(*encZeroDest);
        if (!credited)
            return tefINTERNAL;  // LCOV_EXCL_LINE — preclaim checked
        auto const ser = credited->serialize();
        if (auto const ter = homomorphicAdd(*sleDest, sfConfidentialBalanceInbox, makeSlice(ser)))
            return ter;
    }

    // Dest issuer mirror ⊕ IssuerEncryptedAmount ⊕ Enc(0; e).
    {
        auto const issuerCt = parseElGamalCiphertext(tx[sfIssuerEncryptedAmount]);
        if (!issuerCt)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const credited = issuerCt->add(*encZeroIssuer);
        if (!credited)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const ser = credited->serialize();
        if (auto const ter = homomorphicAdd(*sleDest, sfIssuerEncryptedBalance, makeSlice(ser)))
            return ter;
    }

    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auto const auditorPk = parsePk(sleIssuance->getFieldVL(sfAuditorEncryptionKey));
        if (!auditorPk)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const encZeroAuditor = ElGamalCiphertext::encrypt(0, *auditorPk, *e);
        if (!encZeroAuditor)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const auditorCt = parseElGamalCiphertext(tx[sfAuditorEncryptedAmount]);
        if (!auditorCt)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const credited = auditorCt->add(*encZeroAuditor);
        if (!credited)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const ser = credited->serialize();
        if (auto const ter = homomorphicAdd(*sleDest, sfAuditorEncryptedBalance, makeSlice(ser)))
            return ter;
    }

    // OA / COA unchanged.
    view().update(sleSender);
    view().update(sleDest);
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
