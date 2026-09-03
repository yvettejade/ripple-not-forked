#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential_mpt.h>
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

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <string_view>

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

/** Canonical EncZero under `pk` for an MPT confidential balance.
 *
 * Spec EncZero domain is Account || Issuer || Currency. MPT holder balances
 * are keyed only by MPTokenIssuanceID (no Issuer+Currency pair), so that
 * issuance ID is the token-domain input here.
 *
 * Interface assumption: preferred crypto helper would be
 * `encryptedZero(Point, AccountID, MPTID)`. Until provided, derive r via
 * SHA-512-Half and call `encryptZero`.
 */
[[nodiscard]] std::optional<cm::Ciphertext>
mptEncryptedZero(cm::Point const& pk, AccountID const& account, MPTID const& issuanceID)
{
    static constexpr std::string_view kTag = "EncZero";
    auto const digest =
        sha512Half(Slice{kTag.data(), kTag.size()}, account, issuanceID);
    auto const r = toScalar(u256Slice(digest));
    if (!r)
        return std::nullopt;
    return cm::encryptZero(pk, *r);
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
    MPTID const& issuanceID)
{
    if (!sle.isFieldPresent(field))
    {
        auto zero = mptEncryptedZero(pk, account, issuanceID);
        if (!zero)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        auto sum = cm::ciphertextAdd(*zero, delta);
        if (!sum)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sle.setFieldVL(field, makeSlice(*sum));
        return tesSUCCESS;
    }

    auto const existing = cm::parseCiphertext(makeSlice(sle.getFieldVL(field)));
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
    // #region agent log
    {
        auto const mask = tfUniversalMask;
        auto const flags = ctx.tx.getFlags();
        std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
        ofs << "{\"hypothesisId\":\"H2\",\"location\":\"ConfidentialMPTConvert.cpp:getFlagsMask\","
               "\"message\":\"flags mask\",\"data\":{\"mask\":"
            << mask << ",\"flags\":" << flags << ",\"forbidden\":" << (flags & mask)
            << "},\"timestamp\":"
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count()
            << "}\n";
    }
    // #endregion
    return tfUniversalMask;
}

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    // featureConfidentialTransfer is gated by the TRANSACTION macro
    // (temDISABLED when disabled).

    bool const hasKey = ctx.tx.isFieldPresent(sfHolderEncryptionKey);
    bool const hasProof = ctx.tx.isFieldPresent(sfZKProof);
    // #region agent log
    {
        std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
        ofs << "{\"hypothesisId\":\"H3\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:entry\","
               "\"message\":\"field presence\",\"data\":{\"hasKey\":"
            << (hasKey ? "true" : "false") << ",\"hasProof\":" << (hasProof ? "true" : "false")
            << ",\"flags\":" << ctx.tx.getFlags() << ",\"mptAmount\":" << ctx.tx[sfMPTAmount]
            << "},\"timestamp\":"
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count()
            << "}\n";
    }
    // #endregion
    if (hasKey != hasProof)
    {
        // #region agent log
        {
            std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
            ofs << "{\"hypothesisId\":\"H3\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:"
                   "keyProofMismatch\",\"message\":\"hasKey!=hasProof\",\"data\":{},"
                   "\"timestamp\":"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count()
                << "}\n";
        }
        // #endregion
        return temMALFORMED;
    }

    if (hasKey)
    {
        // Use operator[] so Slice points into STTx-owned STBlob storage.
        // makeSlice(getFieldVL(...)) dangles: getFieldVL returns a temporary Blob.
        auto const key = ctx.tx[sfHolderEncryptionKey];
        auto const proof = ctx.tx[sfZKProof];
        bool const keyOk =
            key.size() == cm::kPointBytes && cm::isValidCompressedPoint(key);
        // #region agent log
        {
            std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
            ofs << "{\"hypothesisId\":\"H4\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:"
                   "keyProof\",\"message\":\"key/proof checks\",\"data\":{\"keySize\":"
                << key.size() << ",\"keyOk\":" << (keyOk ? "true" : "false")
                << ",\"proofSize\":" << proof.size()
                << ",\"expectProof\":" << cm::kKeyRegProofBytes
                << ",\"runId\":\"post-fix\"},\"timestamp\":"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count()
                << "}\n";
        }
        // #endregion
        if (!keyOk)
            return temMALFORMED;
        if (proof.size() != cm::kKeyRegProofBytes)
            return temMALFORMED;
    }

    // sfBlindingFactor is UINT256 (32 bytes). Reject non-scalar values.
    auto const blindSlice = u256Slice(ctx.tx[sfBlindingFactor]);
    bool const blindOk = cm::isValidScalar(blindSlice);
    // #region agent log
    {
        std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
        ofs << "{\"hypothesisId\":\"H5\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:"
               "blinding\",\"message\":\"blinding scalar\",\"data\":{\"blindSize\":"
            << blindSlice.size() << ",\"blindOk\":" << (blindOk ? "true" : "false")
            << "},\"timestamp\":"
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count()
            << "}\n";
    }
    // #endregion
    if (!blindOk)
        return temMALFORMED;

    if (auto const ter = requireCiphertext(ctx.tx[sfHolderEncryptedAmount]); !isTesSuccess(ter))
    {
        // #region agent log
        {
            std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
            ofs << "{\"hypothesisId\":\"H4\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:"
                   "holderCt\",\"message\":\"holder ciphertext rejected\",\"data\":{\"ter\":"
                << TERtoInt(ter) << "},\"timestamp\":"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count()
                << "}\n";
        }
        // #endregion
        return ter;
    }
    if (auto const ter = requireCiphertext(ctx.tx[sfIssuerEncryptedAmount]); !isTesSuccess(ter))
        return ter;
    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const ter = requireCiphertext(ctx.tx[sfAuditorEncryptedAmount]); !isTesSuccess(ter))
            return ter;
    }

    if (ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    // #region agent log
    {
        std::ofstream ofs("/workspace/.cursor/debug-3bb9d4.log", std::ios::app);
        ofs << "{\"hypothesisId\":\"H3\",\"location\":\"ConfidentialMPTConvert.cpp:preflight:"
               "success\",\"message\":\"preflight returning tesSUCCESS\",\"data\":{},"
               "\"timestamp\":"
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count()
            << "}\n";
    }
    // #endregion
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

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, account));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    // Issuer cannot convert its own issuance; vault accounts are holders.
    if (account == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

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
    auto const issuerPk = toPoint((*sleIssuance)[sfIssuerEncryptionKey]);
    if (!holderPk)
        return temBAD_CIPHERTEXT;
    if (!issuerPk)
        return tecNO_PERMISSION;

    std::optional<cm::Point> auditorPk;
    if (auditorConfigured)
    {
        auditorPk = toPoint((*sleIssuance)[sfAuditorEncryptionKey]);
        if (!auditorPk)
            return tecNO_PERMISSION;
    }

    auto const blinding = toScalar(u256Slice(ctx.tx[sfBlindingFactor]));
    if (!blinding)
        return temMALFORMED;

    if (!amountCiphertextValid(
            *holderPk, ctx.tx[sfHolderEncryptedAmount], amount, *blinding) ||
        !amountCiphertextValid(*issuerPk, ctx.tx[sfIssuerEncryptedAmount], amount, *blinding))
        return tecBAD_PROOF;

    if (auditorPk &&
        !amountCiphertextValid(*auditorPk, ctx.tx[sfAuditorEncryptedAmount], amount, *blinding))
        return tecBAD_PROOF;

    if (hasTxKey)
    {
        auto const context = sha512Half(
            Slice{cm::kDomainKeyReg.data(), cm::kDomainKeyReg.size()},
            account,
            issuanceID);
        if (!cm::verifyKeyRegistration(
                *holderPk, ctx.tx[sfZKProof], u256Slice(context)))
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

    bool const initializing = !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) &&
        !sleMpt->isFieldPresent(sfConfidentialBalanceInbox) &&
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance);

    auto const holderKey = tx.isFieldPresent(sfHolderEncryptionKey)
        ? tx[sfHolderEncryptionKey]
        : (*sleMpt)[sfHolderEncryptionKey];
    auto const holderPk = toPoint(holderKey);
    auto const issuerPk = toPoint((*sleIssuance)[sfIssuerEncryptionKey]);
    auto const holderDelta = cm::parseCiphertext(tx[sfHolderEncryptedAmount]);
    auto const issuerDelta = cm::parseCiphertext(tx[sfIssuerEncryptedAmount]);
    if (!holderPk || !issuerPk || !holderDelta || !issuerDelta)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    if (tx.isFieldPresent(sfHolderEncryptionKey))
        sleMpt->setFieldVL(sfHolderEncryptionKey, tx[sfHolderEncryptionKey]);

    if (initializing)
    {
        auto spendingZero = mptEncryptedZero(*holderPk, account, issuanceID);
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
            issuanceID);
        !isTesSuccess(ter))
        return ter;

    if (auto const ter = creditField(
            *sleMpt, sfIssuerEncryptedBalance, *issuerDelta, *issuerPk, account, issuanceID);
        !isTesSuccess(ter))
        return ter;

    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        auto const auditorPk = toPoint((*sleIssuance)[sfAuditorEncryptionKey]);
        auto const auditorDelta = cm::parseCiphertext(tx[sfAuditorEncryptedAmount]);
        if (!auditorPk || !auditorDelta)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        if (auto const ter = creditField(
                *sleMpt,
                sfAuditorEncryptedBalance,
                *auditorDelta,
                *auditorPk,
                account,
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
