#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/Confidential.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <limits>
#include <memory>

namespace xrpl {

NotTEC
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfAccount] == ctx.tx[sfHolder])
        return temMALFORMED;

    auto const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    if (ctx.tx[sfZKProof].size() != kConfidentialClawbackProofLength)
        return temMALFORMED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) *
        static_cast<XRPAmount::value_type>(kConfidentialMptFeeMultiplier);
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const mptId = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptId));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (ctx.tx[sfAccount] != (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    if (!ctx.view.read(keylet::account(ctx.tx[sfHolder])))
        return tecNO_TARGET;

    if (!sleIssuance->isFlag(lsfMPTCanClawback))
        return tecNO_PERMISSION;

    auto const issuerKey = (*sleIssuance)[~sfIssuerEncryptionKey];
    if (!issuerKey)
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(mptId, ctx.tx[sfHolder]));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    auto const amount = ctx.tx[sfMPTAmount];
    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    if (coa < amount)
        return tecINSUFFICIENT_FUNDS;
    if ((*sleIssuance)[sfOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const transcript =
        clawbackTranscript(ctx.tx[sfAccount], ctx.tx[sfHolder], mptId);
    Blob const issuerBalBlob = sleMpt->getFieldVL(sfIssuerEncryptedBalance);
    if (!clawbackVerify(
            makeSlice(issuerBalBlob),
            *issuerKey,
            amount,
            ctx.tx[sfZKProof],
            transcript))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const mptId = ctx_.tx[sfMPTokenIssuanceID];
    auto const holder = ctx_.tx[sfHolder];
    auto const amount = ctx_.tx[sfMPTAmount];
    auto sleIssuance = view().peek(keylet::mptIssuance(mptId));
    auto sleMpt = view().peek(keylet::mptoken(mptId, holder));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // getFieldVL returns Blob by value; keep bytes alive for Slice views.
    auto const holderPkBlob = sleMpt->isFieldPresent(sfHolderEncryptionKey)
        ? sleMpt->getFieldVL(sfHolderEncryptionKey)
        : Blob{};
    auto const issuerPkBlob = sleIssuance->getFieldVL(sfIssuerEncryptionKey);

    if (holderPkBlob.size() == kConfidentialPubKeyLength)
    {
        auto const zHolder =
            encZero(holder, (*sleIssuance)[sfIssuer], mptId, makeSlice(holderPkBlob));
        if (!zHolder)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfConfidentialBalanceSpending, *zHolder);
        sleMpt->setFieldVL(sfConfidentialBalanceInbox, *zHolder);
    }

    auto const zIssuer =
        encZero(holder, (*sleIssuance)[sfIssuer], mptId, makeSlice(issuerPkBlob));
    if (!zIssuer)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldVL(sfIssuerEncryptedBalance, *zIssuer);

    if (auto const auditorKey = (*sleIssuance)[~sfAuditorEncryptionKey])
    {
        auto const zAud = encZero(holder, (*sleIssuance)[sfIssuer], mptId, *auditorKey);
        if (!zAud)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfAuditorEncryptedBalance, *zAud);
    }

    if (sleMpt->isFieldPresent(sfConfidentialBalanceVersion))
    {
        auto const version = sleMpt->getFieldU32(sfConfidentialBalanceVersion);
        sleMpt->setFieldU32(
            sfConfidentialBalanceVersion,
            version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);
    }

    sleIssuance->setFieldU64(
        sfConfidentialOutstandingAmount,
        (*sleIssuance)[~sfConfidentialOutstandingAmount].valueOr(0) - amount);
    sleIssuance->setFieldU64(sfOutstandingAmount, (*sleIssuance)[sfOutstandingAmount] - amount);

    view().update(sleMpt);
    view().update(sleIssuance);
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
