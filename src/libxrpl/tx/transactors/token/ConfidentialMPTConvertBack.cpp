#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

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
    if (account == issuance->at(sfIssuer))
        return tecNO_PERMISSION;
    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance) ||
        !token->isFieldPresent(sfHolderEncryptionKey) ||
        !token->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;
    if (isFrozen(ctx.view, account, MPTIssue{id}))
        return tecLOCKED;
    if (amount > issuance->at(sfConfidentialOutstandingAmount))
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

    // The installed standard libsecp256k1 has no Bulletproof module. This
    // dependency question was raised; fail closed until the specified
    // 128-byte sigma and 688-byte standard Bulletproof verifier are available.
    // Do not invent a fake verifier for the under-specified ConvertBack sigma.
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
    return tefINTERNAL;
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
