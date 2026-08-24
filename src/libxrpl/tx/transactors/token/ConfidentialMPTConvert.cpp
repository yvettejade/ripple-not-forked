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
    // Dedicated-account model: the issuer account cannot convert its own
    // issuance. XLS-0096 §7.3 omitted a result code; sibling confidential
    // transactors use temMALFORMED. Preclaim is required because the issuer
    // comparison needs the issuance object.
    if (account == issuance->at(sfIssuer))
        return temMALFORMED;
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
    if (!parseNonZeroScalar(
            {ctx.tx[sfBlindingFactor].data(), ctx.tx[sfBlindingFactor].size()},
            blinding))
        return tecBAD_PROOF;

    auto verifyEncryption = [&](SField const& cipherField, Slice key) {
        CompressedPoint publicKey;
        Ciphertext ciphertext;
        return parseCompressedPoint(key, publicKey) &&
            parseCiphertext(makeSlice(ctx.tx.getFieldVL(cipherField)), ciphertext) &&
            verifyDeterministicEncryption(
                ciphertext, publicKey, amount, blinding);
    };

    Slice const holderPublicKey = suppliedKey
        ? *suppliedKey
        : makeSlice(token->getFieldVL(sfHolderEncryptionKey));
    if (!verifyEncryption(sfHolderEncryptedAmount, holderPublicKey) ||
        !verifyEncryption(
            sfIssuerEncryptedAmount,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey))) ||
        (auditorRequired &&
         !verifyEncryption(
             sfAuditorEncryptedAmount,
             makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)))))
        return tecBAD_PROOF;

    if (suppliedKey)
    {
        CompressedPoint publicKey;
        SchnorrProof schnorr;
        auto const proof = *ctx.tx[~sfZKProof];
        std::copy(proof.begin(), proof.end(), schnorr.begin());
        // The updated proof document does not define Convert's TxSpecific
        // value. Use Account || 0, matching its self-conversion semantics and
        // the uniform context shape used by ConvertBack.
        auto const context =
            confidential_mpt::proofContext(ctx.tx, account, 0);
        if (!parseCompressedPoint(*suppliedKey, publicKey) ||
            !verifySchnorrProofOfKnowledge(
                publicKey, schnorr, makeSlice(context)))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
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
        issuance->getFieldU64(sfConfidentialOutstandingAmount) + amount;
    if (newConfidential > issuance->at(sfOutstandingAmount))
        return tefINTERNAL;

    if (!token->isFieldPresent(sfHolderEncryptionKey))
    {
        auto const holderKey = ctx_.tx.getFieldVL(sfHolderEncryptionKey);
        auto const holderZero =
            confidential_mpt::canonicalZero(accountID_, id, makeSlice(holderKey));
        auto const issuerZero = confidential_mpt::canonicalZero(
            accountID_,
            id,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey)));
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
                accountID_,
                id,
                makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)));
            if (!auditorZero)
                return tefINTERNAL;
            token->setFieldVL(sfAuditorEncryptedBalance, *auditorZero);
        }
    }

    auto const inbox = confidential_mpt::addCiphertexts(
        makeSlice(token->getFieldVL(sfConfidentialBalanceInbox)),
        ctx_.tx[sfHolderEncryptedAmount]);
    auto const issuer = confidential_mpt::addCiphertexts(
        makeSlice(token->getFieldVL(sfIssuerEncryptedBalance)),
        ctx_.tx[sfIssuerEncryptedAmount]);
    if (!inbox || !issuer)
        return tefINTERNAL;
    token->setFieldVL(sfConfidentialBalanceInbox, *inbox);
    token->setFieldVL(sfIssuerEncryptedBalance, *issuer);

    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const auditor = confidential_mpt::addCiphertexts(
            makeSlice(token->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        if (!auditor)
            return tefINTERNAL;
        token->setFieldVL(sfAuditorEncryptedBalance, *auditor);
    }

    token->setFieldU64(sfMPTAmount, token->at(sfMPTAmount) - amount);
    confidential_mpt::setConfidentialOutstanding(*issuance, newConfidential);
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
