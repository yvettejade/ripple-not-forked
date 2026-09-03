#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>

namespace xrpl {
namespace {

namespace cm = confidential_mpt;

[[nodiscard]] Slice
u256Slice(uint256 const& value)
{
    return Slice{value.data(), value.size()};
}

[[nodiscard]] std::optional<cm::Point>
toPoint(Slice const data)
{
    if (!cm::isValidCompressedPoint(data))
        return std::nullopt;
    cm::Point out{};
    std::memcpy(out.data(), data.data(), cm::kPointBytes);
    return out;
}

[[nodiscard]] std::optional<cm::Scalar>
toScalar(Slice const data)
{
    if (!cm::isValidScalar(data))
        return std::nullopt;
    cm::Scalar out{};
    std::memcpy(out.data(), data.data(), cm::kScalarBytes);
    return out;
}

[[nodiscard]] uint256
makeConvertContext(STTx const& tx)
{
    // The supplemental proof document requires TransactionContextID here but
    // does not define Convert's TxSpecific component. Bind the fields common
    // to Equation (40), including the sequence/ticket replay domain.
    return sha512Half(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
        tx.getAccountID(sfAccount),
        tx[sfMPTokenIssuanceID],
        tx.getSeqProxy().value());
}

[[nodiscard]] bool
amountCiphertextValid(
    cm::Point const& pk,
    Slice const ciphertext,
    std::uint64_t amount,
    cm::Scalar const& blinding)
{
    auto const ct = cm::parseCiphertext(ciphertext);
    return ct && cm::verifyCiphertext(pk, *ct, amount, blinding);
}

[[nodiscard]] NotTEC
requireCiphertext(Slice const data)
{
    if (data.size() != cm::kCiphertextBytes || !cm::parseCiphertext(data))
        return temBAD_CIPHERTEXT;
    return tesSUCCESS;
}

[[nodiscard]] TER
creditField(
    SLE& sle,
    SField const& field,
    cm::Ciphertext const& delta,
    cm::Point const& pk,
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID)
{
    if (!sle.isFieldPresent(field))
    {
        auto zero = confidentialMPTEncryptedZero(pk, account, issuer, issuanceID);
        if (!zero)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        auto sum = cm::ciphertextAdd(*zero, delta);
        if (!sum)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sle.setFieldVL(field, makeSlice(*sum));
        return tesSUCCESS;
    }

    // Keep Blob alive: getFieldVL returns a temporary; makeSlice of that
    // temporary must not outlive the Blob that owns the bytes.
    Blob const existingBlob = sle.getFieldVL(field);
    auto const existing = cm::parseCiphertext(makeSlice(existingBlob));
    if (!existing)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    auto const sum = cm::ciphertextAdd(*existing, delta);
    if (!sum)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sle.setFieldVL(field, makeSlice(*sum));
    return tesSUCCESS;
}

}  // namespace

std::uint32_t
ConfidentialMPTConvert::getFlagsMask(PreflightContext const& ctx)
{
    return tfUniversalMask;
}

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    // featureConfidentialTransfer is gated by the TRANSACTION macro
    // (temDISABLED when disabled).

    bool const hasKey = ctx.tx.isFieldPresent(sfHolderEncryptionKey);
    bool const hasProof = ctx.tx.isFieldPresent(sfZKProof);
    if (hasKey != hasProof)
        return temMALFORMED;

    if (hasKey)
    {
        auto const key = ctx.tx[sfHolderEncryptionKey];
        if (key.size() != cm::kPointBytes || !cm::isValidCompressedPoint(key))
            return temMALFORMED;
        if (ctx.tx.getFieldVL(sfZKProof).size() != cm::kKeyRegProofBytes)
            return temMALFORMED;
    }

    // sfBlindingFactor is UINT256 (32 bytes). Reject non-scalar values.
    if (!cm::isValidScalar(u256Slice(ctx.tx[sfBlindingFactor])))
        return temMALFORMED;

    if (auto const ter = requireCiphertext(makeSlice(ctx.tx.getFieldVL(sfHolderEncryptedAmount)));
        !isTesSuccess(ter))
        return ter;
    if (auto const ter = requireCiphertext(makeSlice(ctx.tx.getFieldVL(sfIssuerEncryptedAmount)));
        !isTesSuccess(ter))
        return ter;
    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const ter =
                requireCiphertext(makeSlice(ctx.tx.getFieldVL(sfAuditorEncryptedAmount)));
            !isTesSuccess(ter))
            return ter;
    }

    if (ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
{
    auto const account = ctx.tx[sfAccount];
    auto const issuanceID = ctx.tx[sfMPTokenIssuanceID];
    auto const amount = ctx.tx[sfMPTAmount];

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    // Issuer cannot convert its own issuance; vault accounts are holders.
    // Checked before the MPToken lookup so the issuer gets temMALFORMED even
    // when no issuer MPToken exists (xls-0096 Convert failure conditions).
    if (account == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    bool const auditorConfigured = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (auditorConfigured != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    if ((*sleMpt)[sfMPTAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    bool const hasTxKey = ctx.tx.isFieldPresent(sfHolderEncryptionKey);
    bool const hasRegisteredKey = sleMpt->isFieldPresent(sfHolderEncryptionKey);
    if (hasTxKey && hasRegisteredKey)
        return tecDUPLICATE;
    if (!hasTxKey && !hasRegisteredKey)
        return tecNO_PERMISSION;

    auto const holderKey =
        hasTxKey ? ctx.tx[sfHolderEncryptionKey] : (*sleMpt)[sfHolderEncryptionKey];
    auto const holderPk = toPoint(holderKey);
    auto const issuerPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfIssuerEncryptionKey)));
    if (!holderPk)
        return temBAD_CIPHERTEXT;
    if (!issuerPk)
        return tecNO_PERMISSION;

    std::optional<cm::Point> auditorPk;
    if (auditorConfigured)
    {
        auditorPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfAuditorEncryptionKey)));
        if (!auditorPk)
            return tecNO_PERMISSION;
    }

    auto const blinding = toScalar(u256Slice(ctx.tx[sfBlindingFactor]));
    if (!blinding)
        return temMALFORMED;

    if (!amountCiphertextValid(
            *holderPk, makeSlice(ctx.tx.getFieldVL(sfHolderEncryptedAmount)), amount, *blinding) ||
        !amountCiphertextValid(
            *issuerPk, makeSlice(ctx.tx.getFieldVL(sfIssuerEncryptedAmount)), amount, *blinding))
        return tecBAD_PROOF;

    if (auditorPk &&
        !amountCiphertextValid(
            *auditorPk, makeSlice(ctx.tx.getFieldVL(sfAuditorEncryptedAmount)), amount, *blinding))
        return tecBAD_PROOF;

    if (hasTxKey)
    {
        auto const context = makeConvertContext(ctx.tx);
        if (!cm::verifyKeyRegistration(
                *holderPk, makeSlice(ctx.tx.getFieldVL(sfZKProof)), u256Slice(context)))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const& tx = ctx_.tx;
    auto const account = accountID_;
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto sleMpt = view().peek(keylet::mptoken(issuanceID, account));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    if (account == (*sleIssuance)[sfIssuer])
        return tefINTERNAL;  // LCOV_EXCL_LINE
    auto const issuer = (*sleIssuance)[sfIssuer];

    bool const initializing = !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) &&
        !sleMpt->isFieldPresent(sfConfidentialBalanceInbox) &&
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance);

    auto const holderKey = tx.isFieldPresent(sfHolderEncryptionKey)
        ? tx[sfHolderEncryptionKey]
        : (*sleMpt)[sfHolderEncryptionKey];
    auto const holderPk = toPoint(holderKey);
    auto const issuerPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfIssuerEncryptionKey)));
    auto const holderDelta = cm::parseCiphertext(makeSlice(tx.getFieldVL(sfHolderEncryptedAmount)));
    auto const issuerDelta = cm::parseCiphertext(makeSlice(tx.getFieldVL(sfIssuerEncryptedAmount)));
    if (!holderPk || !issuerPk || !holderDelta || !issuerDelta)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    if (tx.isFieldPresent(sfHolderEncryptionKey))
        sleMpt->setFieldVL(sfHolderEncryptionKey, makeSlice(tx.getFieldVL(sfHolderEncryptionKey)));

    if (initializing)
    {
        auto spendingZero = confidentialMPTEncryptedZero(*holderPk, account, issuer, issuanceID);
        if (!spendingZero)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfConfidentialBalanceSpending, makeSlice(*spendingZero));
        sleMpt->setFieldU32(sfConfidentialBalanceVersion, 0);
    }

    if (auto const ter = creditField(
            *sleMpt,
            sfConfidentialBalanceInbox,
            *holderDelta,
            *holderPk,
            account,
            issuer,
            issuanceID);
        !isTesSuccess(ter))
        return ter;

    if (auto const ter = creditField(
            *sleMpt,
            sfIssuerEncryptedBalance,
            *issuerDelta,
            *issuerPk,
            account,
            issuer,
            issuanceID);
        !isTesSuccess(ter))
        return ter;

    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auto const auditorPk = toPoint(makeSlice(sleIssuance->getFieldVL(sfAuditorEncryptionKey)));
        auto const auditorDelta =
            cm::parseCiphertext(makeSlice(tx.getFieldVL(sfAuditorEncryptedAmount)));
        if (!auditorPk || !auditorDelta)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        if (auto const ter = creditField(
                *sleMpt,
                sfAuditorEncryptedBalance,
                *auditorDelta,
                *auditorPk,
                account,
                issuer,
                issuanceID);
            !isTesSuccess(ter))
            return ter;
    }

    auto const publicBalance = (*sleMpt)[sfMPTAmount];
    if (publicBalance < amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldU64(sfMPTAmount, publicBalance - amount);

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].valueOr(0);
    if (coa > kMaxMpTokenAmount - amount)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleIssuance->setFieldU64(sfConfidentialOutstandingAmount, coa + amount);

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
