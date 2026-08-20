#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/crypto/confidential/Proofs.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <algorithm>

namespace xrpl {

using namespace crypto::confidential;

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    auto const holderKey = ctx.tx[~sfHolderEncryptionKey];
    auto const proof = ctx.tx[~sfZKProof];
    if (holderKey.has_value() != proof.has_value())
        return temMALFORMED;
    if (holderKey && holderKey->size() != kCompressedPointBytes)
        return temMALFORMED;
    if (proof && proof->size() != kSchnorrProofBytes)
        return temMALFORMED;
    if (ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    if (!confidential_mpt::validCiphertext(ctx.tx[sfHolderEncryptedAmount]) ||
        !confidential_mpt::validCiphertext(ctx.tx[sfIssuerEncryptedAmount]) ||
        (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount) &&
         !confidential_mpt::validCiphertext(ctx.tx[sfAuditorEncryptedAmount])))
        return temBAD_CIPHERTEXT;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const account = ctx.tx[sfAccount];
    auto const amount = ctx.tx[sfMPTAmount];
    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const token = ctx.view.read(keylet::mptoken(id, account));
    if (!issuance || !token)
        return tecOBJECT_NOT_FOUND;
    if (account == issuance->at(sfIssuer))
        return tecNO_PERMISSION;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance) ||
        !issuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;
    if (isFrozen(ctx.view, account, MPTIssue{id}))
        return tecLOCKED;
    if (auto const ter = requireAuth(ctx.view, MPTIssue{id}, account);
        !isTesSuccess(ter))
        return ter;

    auto const auditorRequired =
        issuance->isFieldPresent(sfAuditorEncryptionKey);
    if (auditorRequired != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;
    if (token->at(sfMPTAmount) < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const suppliedKey = ctx.tx[~sfHolderEncryptionKey];
    if (suppliedKey && token->isFieldPresent(sfHolderEncryptionKey))
        return tecDUPLICATE;
    if (!suppliedKey && !token->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    Scalar blinding;
    if (!parseScalar(
            {ctx.tx[sfBlindingFactor].data(),
             ctx.tx[sfBlindingFactor].size()},
            blinding))
        return tecBAD_PROOF;

    auto verifyEncryption = [&](SField const& cipherField, Blob const& key) {
        CompressedPoint publicKey;
        Ciphertext ciphertext;
        return parseCompressedPoint(makeSlice(key), publicKey) &&
            parseCiphertext(makeSlice(ctx.tx[cipherField]), ciphertext) &&
            verifyDeterministicEncryption(
                   ciphertext, publicKey, amount, blinding);
    };

    Blob const holderPublicKey =
        suppliedKey.value_or(token->at(sfHolderEncryptionKey));
    if (!verifyEncryption(sfHolderEncryptedAmount, holderPublicKey) ||
        !verifyEncryption(
            sfIssuerEncryptedAmount,
            issuance->at(sfIssuerEncryptionKey)) ||
        (auditorRequired &&
         !verifyEncryption(
             sfAuditorEncryptedAmount,
             issuance->at(sfAuditorEncryptionKey))))
        return tecBAD_PROOF;

    if (suppliedKey)
    {
        CompressedPoint publicKey;
        SchnorrProof schnorr;
        auto const proof = *ctx.tx[~sfZKProof];
        std::copy(proof.begin(), proof.end(), schnorr.begin());
        auto const context = confidential_mpt::proofContext(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            account,
            id,
            0);
        if (!parseCompressedPoint(makeSlice(*suppliedKey), publicKey) ||
            !verifySchnorrProofOfKnowledge(
                publicKey, schnorr, makeSlice(context)))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(
    ReadView const& view,
    STTx const& tx)
{
    return confidential_mpt::proofBaseFee(view, tx);
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto issuance = view().peek(keylet::mptIssuance(id));
    auto token = view().peek(keylet::mptoken(id, accountID_));
    if (!issuance || !token)
        return tefINTERNAL;

    auto const amount = ctx_.tx[sfMPTAmount];
    auto const newConfidential =
        issuance->at(sfConfidentialOutstandingAmount) + amount;
    if (newConfidential > issuance->at(sfOutstandingAmount))
        return tefINTERNAL;

    if (!token->isFieldPresent(sfHolderEncryptionKey))
    {
        auto const holderKey = ctx_.tx.at(sfHolderEncryptionKey);
        auto const holderZero =
            confidential_mpt::canonicalZero(accountID_, id, holderKey);
        auto const issuerZero = confidential_mpt::canonicalZero(
            accountID_, id, issuance->at(sfIssuerEncryptionKey));
        if (!holderZero || !issuerZero)
            return tefINTERNAL;

        token->setFieldVL(sfHolderEncryptionKey, holderKey);
        token->setFieldVL(sfConfidentialBalanceSpending, *holderZero);
        token->setFieldVL(sfConfidentialBalanceInbox, *holderZero);
        token->setFieldVL(sfIssuerEncryptedBalance, *issuerZero);
        token->setFieldU32(sfConfidentialBalanceVersion, 0);

        if (issuance->isFieldPresent(sfAuditorEncryptionKey))
        {
            auto const auditorZero = confidential_mpt::canonicalZero(
                accountID_, id, issuance->at(sfAuditorEncryptionKey));
            if (!auditorZero)
                return tefINTERNAL;
            token->setFieldVL(sfAuditorEncryptedBalance, *auditorZero);
        }
    }

    auto const inbox = confidential_mpt::addCiphertexts(
        token->at(sfConfidentialBalanceInbox),
        ctx_.tx.at(sfHolderEncryptedAmount));
    auto const issuer = confidential_mpt::addCiphertexts(
        token->at(sfIssuerEncryptedBalance),
        ctx_.tx.at(sfIssuerEncryptedAmount));
    if (!inbox || !issuer)
        return tefINTERNAL;
    token->setFieldVL(sfConfidentialBalanceInbox, *inbox);
    token->setFieldVL(sfIssuerEncryptedBalance, *issuer);

    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const auditor = confidential_mpt::addCiphertexts(
            token->at(sfAuditorEncryptedBalance),
            ctx_.tx.at(sfAuditorEncryptedAmount));
        if (!auditor)
            return tefINTERNAL;
        token->setFieldVL(sfAuditorEncryptedBalance, *auditor);
    }

    token->setFieldU64(sfMPTAmount, token->at(sfMPTAmount) - amount);
    issuance->setFieldU64(
        sfConfidentialOutstandingAmount, newConfidential);
    view().update(token);
    view().update(issuance);
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
