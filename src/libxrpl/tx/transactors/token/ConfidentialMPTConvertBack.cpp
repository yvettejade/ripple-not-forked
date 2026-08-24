#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

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
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfMPTAmount] == 0 || ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;
    if (ctx.tx[sfZKProof].size() != confidential_mpt::kConvertBackProofBytes)
        return temMALFORMED;
    if (!confidential_mpt::validPoint(ctx.tx[sfBalanceCommitment]))
        return temMALFORMED;
    if (!confidential_mpt::validCiphertext(ctx.tx[sfHolderEncryptedAmount]) ||
        !confidential_mpt::validCiphertext(ctx.tx[sfIssuerEncryptedAmount]) ||
        (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount) &&
         !confidential_mpt::validCiphertext(ctx.tx[sfAuditorEncryptedAmount])))
        return temBAD_CIPHERTEXT;
    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const account = ctx.tx[sfAccount];
    auto const amount = ctx.tx[sfMPTAmount];
    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const token = ctx.view.read(keylet::mptoken(id, account));
    if (!issuance || !token)
        return tecOBJECT_NOT_FOUND;
    // XLS-0096 §10.4.1.2. Issuer identity is on-ledger, so this lives in
    // preclaim rather than preflight.
    if (account == issuance->at(sfIssuer))
        return temMALFORMED;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance) ||
        !token->isFieldPresent(sfHolderEncryptionKey) ||
        !token->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;
    // XLS-0096 named this terFROZEN; this tree already has terLOCKED for MPT
    // locks and no terFROZEN enumerator.
    if (isFrozen(ctx.view, account, MPTIssue{id}))
        return terLOCKED;
    if (amount > issuance->getFieldU64(sfConfidentialOutstandingAmount))
        return tecINSUFFICIENT_FUNDS;

    auto const auditorRequired =
        issuance->isFieldPresent(sfAuditorEncryptionKey);
    if (auditorRequired != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    Scalar blinding;
    if (!parseNonZeroScalar(
            {ctx.tx[sfBlindingFactor].data(), ctx.tx[sfBlindingFactor].size()},
            blinding))
        return tecBAD_PROOF;
    auto verifyEncryption = [&](SField const& field, Slice key) {
        CompressedPoint publicKey;
        Ciphertext ciphertext;
        return parseCompressedPoint(key, publicKey) &&
            parseCiphertext(makeSlice(ctx.tx.getFieldVL(field)), ciphertext) &&
            verifyDeterministicEncryption(
                ciphertext, publicKey, amount, blinding);
    };
    if (!verifyEncryption(
            sfHolderEncryptedAmount,
            makeSlice(token->getFieldVL(sfHolderEncryptionKey))) ||
        !verifyEncryption(
            sfIssuerEncryptedAmount,
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey))) ||
        (auditorRequired &&
         !verifyEncryption(
             sfAuditorEncryptedAmount,
             makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)))))
        return tecBAD_PROOF;

    CompressedPoint holderKey;
    CompressedPoint balanceCommitment;
    Ciphertext balanceCiphertext;
    if (!parseCompressedPoint(
            makeSlice(token->getFieldVL(sfHolderEncryptionKey)), holderKey) ||
        !parseCompressedPoint(
            ctx.tx[sfBalanceCommitment], balanceCommitment) ||
        !parseCiphertext(
            makeSlice(token->getFieldVL(sfConfidentialBalanceSpending)),
            balanceCiphertext))
        return tecBAD_PROOF;

    BalanceSigmaProof sigma;
    auto const proof = ctx.tx.getFieldVL(sfZKProof);
    std::copy_n(proof.begin(), sigma.size(), sigma.begin());
    auto const context = confidential_mpt::proofContext(
        ctx.tx,
        account,
        token->at(sfConfidentialBalanceVersion));
    if (!verifyBalanceSigmaProof(
            {.senderPublicKey = holderKey,
             .balanceCiphertext = balanceCiphertext,
             .balanceCommitment = balanceCommitment},
            sigma,
            makeSlice(context)))
        return tecBAD_PROOF;

    // The updated document specifies the compact balance sigma proof above.
    // It still leaves the 688-byte Bulletproof's generator derivation and wire
    // encoding to a citation, and that encoding is incompatible with the
    // maintained secp256k1-zkp implementation. Keep the range check fail-closed.
    return tecBAD_PROOF;
}

XRPAmount
ConfidentialMPTConvertBack::calculateBaseFee(
    ReadView const& view,
    STTx const& tx)
{
    return confidential_mpt::proofBaseFee(view, tx);
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto issuance = view().peek(keylet::mptIssuance(id));
    auto token = view().peek(keylet::mptoken(id, accountID_));
    if (!issuance || !token)
        return tefINTERNAL;

    auto const amount = ctx_.tx[sfMPTAmount];
    auto const coa = issuance->getFieldU64(sfConfidentialOutstandingAmount);
    if (amount > coa)
        return tefINTERNAL;
    if (token->at(sfMPTAmount) > kMaxMpTokenAmount - amount)
        return tefINTERNAL;

    auto const spending = confidential_mpt::subtractCiphertexts(
        makeSlice(token->getFieldVL(sfConfidentialBalanceSpending)),
        ctx_.tx[sfHolderEncryptedAmount]);
    auto const issuer = confidential_mpt::subtractCiphertexts(
        makeSlice(token->getFieldVL(sfIssuerEncryptedBalance)),
        ctx_.tx[sfIssuerEncryptedAmount]);
    if (!spending || !issuer)
        return tefINTERNAL;

    token->setFieldVL(sfConfidentialBalanceSpending, *spending);
    token->setFieldVL(sfIssuerEncryptedBalance, *issuer);
    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const auditor = confidential_mpt::subtractCiphertexts(
            makeSlice(token->getFieldVL(sfAuditorEncryptedBalance)),
            ctx_.tx[sfAuditorEncryptedAmount]);
        if (!auditor)
            return tefINTERNAL;
        token->setFieldVL(sfAuditorEncryptedBalance, *auditor);
    }

    // ConvertBack restores public form. XLS-0096's worked example decreased
    // OA; the normative text (clarified) keeps OA unchanged and only lowers
    // COA.
    token->setFieldU64(sfMPTAmount, token->at(sfMPTAmount) + amount);
    token->setFieldU32(
        sfConfidentialBalanceVersion,
        token->at(sfConfidentialBalanceVersion) + 1u);
    confidential_mpt::setConfidentialOutstanding(*issuance, coa - amount);
    view().update(token);
    view().update(issuance);
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
