#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Confidential.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>

namespace xrpl {
namespace {

[[nodiscard]] TER
debitCiphertext(SLE& sle, SField const& field, Slice const& delta)
{
    if (!sle.isFieldPresent(field))
        return tecNO_PERMISSION;
    auto const next = elgamalSub(makeSlice(sle.getFieldVL(field)), delta);
    if (!next)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sle.setFieldVL(field, *next);
    return tesSUCCESS;
}

}  // namespace

NotTEC
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    auto const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    if (!isConfidentialScalar(ctx.tx[sfBlindingFactor]))
        return temMALFORMED;

    if (!isConfidentialCiphertext(ctx.tx[sfHolderEncryptedAmount]) ||
        !isConfidentialCiphertext(ctx.tx[sfIssuerEncryptedAmount]))
        return temBAD_CIPHERTEXT;

    if (auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
        auditorAmount && !isConfidentialCiphertext(*auditorAmount))
        return temBAD_CIPHERTEXT;

    if (!isConfidentialPubKey(ctx.tx[sfBalanceCommitment]))
        return temMALFORMED;

    if (ctx.tx[sfZKProof].size() != kConfidentialConvertBackZkLength)
        return temMALFORMED;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvertBack::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) *
        static_cast<XRPAmount::value_type>(kConfidentialMptFeeMultiplier);
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
{
    auto const mptId = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptId));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (ctx.tx[sfAccount] == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(mptId, ctx.tx[sfAccount]));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceVersion))
        return tecNO_PERMISSION;

    auto const issuerKey = (*sleIssuance)[~sfIssuerEncryptionKey];
    if (!issuerKey)
        return tecNO_PERMISSION;

    auto const amount = ctx.tx[sfMPTAmount];
    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].value_or(0);
    if (coa < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const auditorKey = (*sleIssuance)[~sfAuditorEncryptionKey];
    auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
    if (static_cast<bool>(auditorKey) != static_cast<bool>(auditorAmount))
        return tecNO_PERMISSION;

    auto const r = ctx.tx[sfBlindingFactor];
    // getFieldVL returns Blob by value; keep bytes alive for any Slice view.
    Blob const holderPkBlob = sleMpt->getFieldVL(sfHolderEncryptionKey);
    Blob const spendingBlob = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
    Slice const holderPk = makeSlice(holderPkBlob);
    if (!elgamalMatches(ctx.tx[sfHolderEncryptedAmount], holderPk, amount, r) ||
        !elgamalMatches(ctx.tx[sfIssuerEncryptedAmount], *issuerKey, amount, r))
        return tecBAD_PROOF;
    if (auditorKey && !elgamalMatches(*auditorAmount, *auditorKey, amount, r))
        return tecBAD_PROOF;

    MPTIssue const issue{mptId};
    if (isFrozen(ctx.view, ctx.tx[sfAccount], issue))
        return tecLOCKED;

    auto const transcript = convertBackTranscript(
        ctx.tx[sfAccount], mptId, sleMpt->getFieldU32(sfConfidentialBalanceVersion));
    if (!convertBackVerify(
            holderPk,
            *issuerKey,
            auditorKey,
            makeSlice(spendingBlob),
            amount,
            ctx.tx[sfHolderEncryptedAmount],
            ctx.tx[sfIssuerEncryptedAmount],
            auditorAmount,
            r,
            ctx.tx[sfBalanceCommitment],
            ctx.tx[sfZKProof],
            transcript))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const mptId = ctx_.tx[sfMPTokenIssuanceID];
    auto const amount = ctx_.tx[sfMPTAmount];
    auto sleIssuance = view().peek(keylet::mptIssuance(mptId));
    auto sleMpt = view().peek(keylet::mptoken(mptId, accountID_));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // ValueProxy clears SoeDefault MPTAmount when the value is 0.
    (*sleMpt)[sfMPTAmount] = (*sleMpt)[sfMPTAmount] + amount;
    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].valueOr(0);
    sleIssuance->setFieldU64(sfConfidentialOutstandingAmount, coa - amount);

    if (auto const ter = debitCiphertext(
            *sleMpt, sfConfidentialBalanceSpending, ctx_.tx[sfHolderEncryptedAmount]))
        return ter;
    if (auto const ter =
            debitCiphertext(*sleMpt, sfIssuerEncryptedBalance, ctx_.tx[sfIssuerEncryptedAmount]))
        return ter;
    if (auto const auditorAmount = ctx_.tx[~sfAuditorEncryptedAmount])
    {
        if (auto const ter =
                debitCiphertext(*sleMpt, sfAuditorEncryptedBalance, *auditorAmount))
            return ter;
    }

    auto const version = sleMpt->getFieldU32(sfConfidentialBalanceVersion);
    sleMpt->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

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
