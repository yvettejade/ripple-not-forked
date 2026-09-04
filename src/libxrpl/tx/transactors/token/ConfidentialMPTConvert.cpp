#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
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

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace xrpl {
namespace {

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

[[nodiscard]] std::optional<Secp256k1Point>
parsePk(Slice key)
{
    if (key.size() != Secp256k1Point::kSerializedSize)
        return std::nullopt;
    return Secp256k1Point::parse(key);
}

[[nodiscard]] TER
homomorphicAccumulate(
    SLE& sle,
    SF_VL const& field,
    Slice addition,
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID,
    Secp256k1Point const& pk)
{
    if (!sle.isFieldPresent(field))
    {
        // Spec: absent balance treated as EncZero then add.
        auto zero = encZero(account, issuer, issuanceID, pk);
        if (!zero)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto sum = homomorphicAddCiphertexts(makeSlice(*zero), addition);
        if (!sum)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        sle.setFieldVL(field, *sum);
        return tesSUCCESS;
    }

    auto sum = homomorphicAddCiphertexts(makeSlice(sle.getFieldVL(field)), addition);
    if (!sum)
        return tefINTERNAL;  // LCOV_EXCL_LINE
    sle.setFieldVL(field, *sum);
    return tesSUCCESS;
}

}  // namespace

bool
ConfidentialMPTConvert::checkExtraFeatures(PreflightContext const& ctx)
{
    return ctx.rules.enabled(featureConfidentialTransfer);
}

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    // Amendment also gated via transactions.macro feature + checkExtraFeatures.
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    auto const& tx = ctx.tx;
    bool const hasHolderKey = tx.isFieldPresent(sfHolderEncryptionKey);
    bool const hasZKProof = tx.isFieldPresent(sfZKProof);

    // HolderEncryptionKey present xor ZKProof present.
    if (hasHolderKey != hasZKProof)
        return temMALFORMED;

    if (hasHolderKey)
    {
        auto const key = tx[sfHolderEncryptionKey];
        if (key.size() != Secp256k1Point::kSerializedSize)
            return temMALFORMED;
        if (!Secp256k1Point::parse(key))
            return temMALFORMED;
    }

    // UINT256 is always 32 bytes when present (required). Length check retained
    // for parity with the VL form of the same conceptual field.
    {
        auto const& bf = tx[sfBlindingFactor];
        if (bf.size() != Secp256k1Scalar::kSerializedSize)
            return temMALFORMED;  // LCOV_EXCL_LINE
    }

    if (hasZKProof)
    {
        auto const proof = tx[sfZKProof];
        if (proof.size() != kRegisterPoKSize)
            return temMALFORMED;
    }

    if (auto const r = checkCiphertextField(tx, sfHolderEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfIssuerEncryptedAmount, true))
        return r;
    if (auto const r = checkCiphertextField(tx, sfAuditorEncryptedAmount, false))
        return r;

    // uint64 cannot be < 0; reject amounts above protocol max.
    if (tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    // Spec §14: confidential convert costs 10× the reference base fee.
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
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

    // Spec 13.5: Convert from issuer is invalid. Spec 7 does not list a tem*
    // for this in 7.3.2; prefer tecNO_PERMISSION (preclaim returning tem* is
    // unusual in this codebase; Send uses temMALFORMED in data verification).
    if (account == (*sleIssuance)[sfIssuer])
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if ((*sleMpt)[sfMPTAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    bool const hasHolderKeyTx = tx.isFieldPresent(sfHolderEncryptionKey);
    bool const hasHolderKeyLedger = sleMpt->isFieldPresent(sfHolderEncryptionKey);

    if (hasHolderKeyTx && hasHolderKeyLedger)
        return tecDUPLICATE;

    if (!hasHolderKeyTx && !hasHolderKeyLedger)
        return tecNO_PERMISSION;

    bool const hasAuditorKey = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    bool const hasAuditorAmt = tx.isFieldPresent(sfAuditorEncryptedAmount);
    if (hasAuditorKey != hasAuditorAmt)
        return tecNO_PERMISSION;

    auto const issuer = (*sleIssuance)[sfIssuer];

    // Resolve holder public key used for reconstruct / PoK.
    Blob holderKeyBlob;
    if (hasHolderKeyTx)
    {
        auto const key = tx[sfHolderEncryptionKey];
        holderKeyBlob.assign(key.data(), key.data() + key.size());
    }
    else
    {
        holderKeyBlob = sleMpt->getFieldVL(sfHolderEncryptionKey);
    }

    auto const holderPk = parsePk(holderKeyBlob);
    if (!holderPk)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE

    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!issuerPk)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE

    auto const& bf = tx[sfBlindingFactor];
    auto const blinding = Secp256k1Scalar::parse(Slice(bf.data(), bf.size()));
    if (!blinding)
        return tecBAD_PROOF;

    auto const holderCt = parseElGamalCiphertext(tx[sfHolderEncryptedAmount]);
    auto const issuerCt = parseElGamalCiphertext(tx[sfIssuerEncryptedAmount]);
    if (!holderCt || !issuerCt)
        return temBAD_CIPHERTEXT;  // LCOV_EXCL_LINE — preflight validated

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

    if (hasHolderKeyTx)
    {
        // Spec gap: Convert PoK addendum omits TxSpecific; core binding only.
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(tx.getTxnType()),
            account,
            issuanceID,
            tx.getSeqProxy().value());
        if (!verifyRegisterPoK(*holderPk, tx[sfZKProof], makeSlice(ctxID)))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = tx[sfAccount];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto const sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const issuer = (*sleIssuance)[sfIssuer];

    // Decrease public MPTAmount (0 allowed — key opt-in only).
    (*sleMpt)[sfMPTAmount] = (*sleMpt)[sfMPTAmount] - amount;

    // Increase confidential outstanding on the issuance.
    (*sleIssuance)[sfConfidentialOutstandingAmount] =
        (*sleIssuance)[sfConfidentialOutstandingAmount] + amount;

    bool const firstInit = !sleMpt->isFieldPresent(sfHolderEncryptionKey) &&
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) &&
        !sleMpt->isFieldPresent(sfConfidentialBalanceInbox);

    if (tx.isFieldPresent(sfHolderEncryptionKey))
        sleMpt->setFieldVL(sfHolderEncryptionKey, tx[sfHolderEncryptionKey]);

    auto const holderPk = parsePk(sleMpt->getFieldVL(sfHolderEncryptionKey));
    if (!holderPk)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!issuerPk)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    if (auto const ter = homomorphicAccumulate(
            *sleMpt,
            sfConfidentialBalanceInbox,
            tx[sfHolderEncryptedAmount],
            account,
            issuer,
            issuanceID,
            *holderPk))
        return ter;

    if (auto const ter = homomorphicAccumulate(
            *sleMpt,
            sfIssuerEncryptedBalance,
            tx[sfIssuerEncryptedAmount],
            account,
            issuer,
            issuanceID,
            *issuerPk))
        return ter;

    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auto const auditorPk = parsePk(sleIssuance->getFieldVL(sfAuditorEncryptionKey));
        if (!auditorPk)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        if (auto const ter = homomorphicAccumulate(
                *sleMpt,
                sfAuditorEncryptedBalance,
                tx[sfAuditorEncryptedAmount],
                account,
                issuer,
                issuanceID,
                *auditorPk))
            return ter;
    }

    // First confidential init: spending = EncZero(holder), version = 0.
    if (firstInit || !sleMpt->isFieldPresent(sfConfidentialBalanceSpending))
    {
        auto zero = encZero(account, issuer, issuanceID, *holderPk);
        if (!zero)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfConfidentialBalanceSpending, *zero);
        if (!sleMpt->isFieldPresent(sfConfidentialBalanceVersion))
            (*sleMpt)[sfConfidentialBalanceVersion] = 0;
    }

    view().update(sleMpt);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvert::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTConvert::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
