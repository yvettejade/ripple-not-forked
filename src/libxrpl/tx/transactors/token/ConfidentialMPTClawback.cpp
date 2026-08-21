#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

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
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;
    if (ctx.tx[sfZKProof].size() != kSchnorrProofBytes)
        return temMALFORMED;
    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const holder = ctx.tx[sfHolder];
    auto const amount = ctx.tx[sfMPTAmount];
    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const token = ctx.view.read(keylet::mptoken(id, holder));
    if (!issuance || !token)
        return tecOBJECT_NOT_FOUND;
    if (ctx.tx[sfAccount] != issuance->at(sfIssuer))
        return tecNO_PERMISSION;
    if (!issuance->isFlag(lsfMPTCanClawback) ||
        !issuance->isFieldPresent(sfIssuerEncryptionKey) ||
        !token->isFieldPresent(sfIssuerEncryptedBalance) ||
        !token->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    CompressedPoint issuerPk;
    Ciphertext issuerCt;
    SchnorrProof proof;
    auto const proofBlob = ctx.tx.getFieldVL(sfZKProof);
    if (proofBlob.size() != proof.size())
        return temMALFORMED;
    std::copy(proofBlob.begin(), proofBlob.end(), proof.begin());
    auto const context = confidential_mpt::proofContext(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
        holder,
        id,
        token->at(sfConfidentialBalanceVersion));
    if (!parseCompressedPoint(
            makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey)), issuerPk) ||
        !parseCiphertext(
            makeSlice(token->getFieldVL(sfIssuerEncryptedBalance)), issuerCt) ||
        !verifyClawbackProof(
            issuerPk, issuerCt, amount, proof, makeSlice(context)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return confidential_mpt::proofBaseFee(view, tx);
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto const holder = ctx_.tx[sfHolder];
    auto const amount = ctx_.tx[sfMPTAmount];
    auto issuance = view().peek(keylet::mptIssuance(id));
    auto token = view().peek(keylet::mptoken(id, holder));
    if (!issuance || !token)
        return tefINTERNAL;

    auto const coa = issuance->getFieldU64(sfConfidentialOutstandingAmount);
    auto const oa = issuance->at(sfOutstandingAmount);
    if (amount > coa || amount > oa)
        return tefINTERNAL;

    auto const holderZero = confidential_mpt::canonicalZero(
        holder, id, makeSlice(token->getFieldVL(sfHolderEncryptionKey)));
    auto const issuerZero = confidential_mpt::canonicalZero(
        holder, id, makeSlice(issuance->getFieldVL(sfIssuerEncryptionKey)));
    if (!holderZero || !issuerZero)
        return tefINTERNAL;

    token->setFieldVL(sfConfidentialBalanceSpending, *holderZero);
    token->setFieldVL(sfConfidentialBalanceInbox, *holderZero);
    token->setFieldVL(sfIssuerEncryptedBalance, *issuerZero);
    if (issuance->isFieldPresent(sfAuditorEncryptionKey))
    {
        auto const auditorZero = confidential_mpt::canonicalZero(
            holder,
            id,
            makeSlice(issuance->getFieldVL(sfAuditorEncryptionKey)));
        if (!auditorZero)
            return tefINTERNAL;
        token->setFieldVL(sfAuditorEncryptedBalance, *auditorZero);
    }
    token->setFieldU32(
        sfConfidentialBalanceVersion,
        token->at(sfConfidentialBalanceVersion) + 1u);

    confidential_mpt::setConfidentialOutstanding(*issuance, coa - amount);
    issuance->setFieldU64(sfOutstandingAmount, oa - amount);
    view().update(token);
    view().update(issuance);
    return tesSUCCESS;
}

void
ConfidentialMPTClawback::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTClawback::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
