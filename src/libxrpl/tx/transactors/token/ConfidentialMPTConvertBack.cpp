#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/Bulletproofs.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
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

constexpr std::size_t kConvertBackZkProofSize = kConvertBackSigmaSize + kSingleBulletproofSize;

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

[[nodiscard]] std::array<std::uint8_t, AccountID::kBytes + 4>
convertBackTxSpecific(AccountID const& account, std::uint32_t version)
{
    std::array<std::uint8_t, AccountID::kBytes + 4> out{};
    std::memcpy(out.data(), account.data(), AccountID::kBytes);
    out[AccountID::kBytes] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    out[AccountID::kBytes + 1] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    out[AccountID::kBytes + 2] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    out[AccountID::kBytes + 3] = static_cast<std::uint8_t>(version & 0xff);
    return out;
}

}  // namespace

bool
ConfidentialMPTConvertBack::checkExtraFeatures(PreflightContext const& ctx)
{
    return ctx.rules.enabled(featureConfidentialTransfer);
}

NotTEC
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    auto const& tx = ctx.tx;
    auto const& bf = tx[sfBlindingFactor];
    if (bf.size() != Secp256k1Scalar::kSerializedSize)
        return temMALFORMED;  // LCOV_EXCL_LINE

    if (auto const r = checkCiphertextField(tx, sfHolderEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfIssuerEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfAuditorEncryptedAmount, false))
        return r;

    auto const pc = tx[sfBalanceCommitment];
    if (pc.size() != Secp256k1Point::kSerializedSize)
        return temMALFORMED;
    if (!Secp256k1Point::parse(pc))
        return temMALFORMED;

    auto const proof = tx[sfZKProof];
    if (proof.size() != kConvertBackZkProofSize)
        return temMALFORMED;

    auto const amount = tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvertBack::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const account = tx[sfAccount];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    // Spec lists temMALFORMED for issuer; preclaim uses tecNO_PERMISSION.
    if (account == (*sleIssuance)[sfIssuer])
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance))
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    bool const hasAuditorAmt = tx.isFieldPresent(sfAuditorEncryptedAmount);
    if (hasAuditorKey != hasAuditorAmt)
        return tecNO_PERMISSION;

    if ((*sleIssuance)[sfConfidentialOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    if (sleMpt->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;  // Spec 10.4.2.9 names terFROZEN; MPT lock is tecLOCKED.

    auto const holderPk = parsePk(sleMpt->getFieldVL(sfHolderEncryptionKey));
    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!holderPk || !issuerPk)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE

    auto const blinding =
        Secp256k1Scalar::parse(Slice(tx[sfBlindingFactor].data(), tx[sfBlindingFactor].size()));
    if (!blinding)
        return tecBAD_PROOF;

    auto const holderCt = parseElGamalCiphertext(tx[sfHolderEncryptedAmount]);
    auto const issuerCt = parseElGamalCiphertext(tx[sfIssuerEncryptedAmount]);
    if (!holderCt || !issuerCt)
        return temBAD_CIPHERTEXT;  // LCOV_EXCL_LINE

    if (!verifyPlaintextElGamal(*holderCt, amount, *holderPk, *blinding))
        return tecBAD_PROOF;
    if (!verifyPlaintextElGamal(*issuerCt, amount, *issuerPk, *blinding))
        return tecBAD_PROOF;

    if (hasAuditorAmt)
    {
        auto const auditorPk = parsePk(sleIssuance->getFieldVL(sfAuditorEncryptionKey));
        if (!auditorPk)
            return tecNO_PERMISSION;  // LCOV_EXCL_LINE
        auto const auditorCt = parseElGamalCiphertext(tx[sfAuditorEncryptedAmount]);
        if (!auditorCt)
            return temBAD_CIPHERTEXT;  // LCOV_EXCL_LINE
        if (!verifyPlaintextElGamal(*auditorCt, amount, *auditorPk, *blinding))
            return tecBAD_PROOF;
    }

    auto const pcB = Secp256k1Point::parse(tx[sfBalanceCommitment]);
    if (!pcB)
        return temMALFORMED;  // LCOV_EXCL_LINE

    auto const spendingCt =
        parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
    if (!spendingCt)
        return tecNO_PERMISSION;

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].value_or(0);
    auto const specific = convertBackTxSpecific(account, version);
    auto const ctxID = confidentialTxContextID(
        static_cast<std::uint16_t>(tx.getTxnType()),
        account,
        issuanceID,
        tx.getSeqProxy().value(),
        makeSlice(specific));

    auto const proof = tx[sfZKProof];
    Slice const sigma(proof.data(), kConvertBackSigmaSize);
    Slice const bp(proof.data() + kConvertBackSigmaSize, kSingleBulletproofSize);

    if (!verifyConvertBackSigma(*holderPk, *spendingCt, *pcB, sigma, makeSlice(ctxID)))
        return tecBAD_PROOF;

    auto const mG = generatorMultiply(Secp256k1Field::fromUint64(amount));
    if (!mG)
        return tecBAD_PROOF;  // LCOV_EXCL_LINE
    auto const pcRem = pointSubtract(*pcB, *mG);
    if (!pcRem)
        return tecBAD_PROOF;
    if (!verifyRange64(*pcRem, bp))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = tx[sfAccount];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto const sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto const sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleIssuance || !sleMpt)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    (*sleMpt)[sfMPTAmount] = (*sleMpt)[sfMPTAmount] + amount;
    (*sleIssuance)[sfConfidentialOutstandingAmount] =
        (*sleIssuance)[sfConfidentialOutstandingAmount] - amount;

    if (auto const ter = homomorphicSubtract(
            *sleMpt, sfConfidentialBalanceSpending, tx[sfHolderEncryptedAmount]))
        return ter;
    if (auto const ter =
            homomorphicSubtract(*sleMpt, sfIssuerEncryptedBalance, tx[sfIssuerEncryptedAmount]))
        return ter;
    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const ter = homomorphicSubtract(
                *sleMpt, sfAuditorEncryptedBalance, tx[sfAuditorEncryptedAmount]))
            return ter;
    }

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].valueOr(0);
    (*sleMpt)[sfConfidentialBalanceVersion] = version + 1;

    view().update(sleMpt);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvertBack::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTConvertBack::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
