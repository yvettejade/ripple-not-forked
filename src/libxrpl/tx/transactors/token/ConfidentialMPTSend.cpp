#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Confidential.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
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
#include <optional>

namespace xrpl {
namespace {

[[nodiscard]] TER
creditCiphertext(SLE& sle, SField const& field, Slice const& delta)
{
    if (!sle.isFieldPresent(field))
    {
        sle.setFieldVL(field, delta);
        return tesSUCCESS;
    }
    auto const sum = elgamalAdd(makeSlice(sle.getFieldVL(field)), delta);
    if (!sum)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sle.setFieldVL(field, *sum);
    return tesSUCCESS;
}

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

bool
ConfidentialMPTSend::checkExtraFeatures(PreflightContext const& ctx)
{
    return !ctx.tx.isFieldPresent(sfCredentialIDs) || ctx.rules.enabled(featureCredentials);
}

NotTEC
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfAccount] == ctx.tx[sfDestination])
        return temMALFORMED;

    if (auto const err = credentials::checkFields(ctx.tx, ctx.j); !isTesSuccess(err))
        return err;

    if (ctx.tx[sfZKProof].size() != kConfidentialSendZkLength)
        return temMALFORMED;

    if (!isConfidentialPubKey(ctx.tx[sfBalanceCommitment]) ||
        !isConfidentialPubKey(ctx.tx[sfAmountCommitment]))
        return temMALFORMED;

    if (!isConfidentialCiphertext(ctx.tx[sfSenderEncryptedAmount]) ||
        !isConfidentialCiphertext(ctx.tx[sfDestinationEncryptedAmount]) ||
        !isConfidentialCiphertext(ctx.tx[sfIssuerEncryptedAmount]))
        return temBAD_CIPHERTEXT;

    if (auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
        auditorAmount && !isConfidentialCiphertext(*auditorAmount))
        return temBAD_CIPHERTEXT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) *
        static_cast<XRPAmount::value_type>(kConfidentialMptFeeMultiplier);
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const mptId = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptId));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (ctx.tx[sfAccount] == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    auto const dst = ctx.tx[sfDestination];
    auto const sleDstAcct = ctx.view.read(keylet::account(dst));
    if (!sleDstAcct)
        return tecNO_TARGET;

    if (!sleIssuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;
    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;
    if ((*sleIssuance)[~sfTransferFee].value_or(0) != 0)
        return tecNO_PERMISSION;

    auto const issuerKey = (*sleIssuance)[~sfIssuerEncryptionKey];
    if (!issuerKey)
        return tecNO_PERMISSION;

    auto const sleSrc = ctx.view.read(keylet::mptoken(mptId, ctx.tx[sfAccount]));
    auto const sleDst = ctx.view.read(keylet::mptoken(mptId, dst));
    if (!sleSrc || !sleDst)
        return tecOBJECT_NOT_FOUND;

    if (!sleSrc->isFieldPresent(sfHolderEncryptionKey) ||
        !sleSrc->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleSrc->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleSrc->isFieldPresent(sfConfidentialBalanceVersion) ||
        !sleDst->isFieldPresent(sfHolderEncryptionKey) ||
        !sleDst->isFieldPresent(sfConfidentialBalanceInbox))
        return tecNO_PERMISSION;

    auto const auditorKey = (*sleIssuance)[~sfAuditorEncryptionKey];
    auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
    if (static_cast<bool>(auditorKey) != static_cast<bool>(auditorAmount))
        return tecNO_PERMISSION;

    MPTIssue const issue{mptId};
    if (isFrozen(ctx.view, ctx.tx[sfAccount], issue) || isFrozen(ctx.view, dst, issue))
        return tecLOCKED;

    if (auto const ter = requireAuth(ctx.view, issue, ctx.tx[sfAccount]); !isTesSuccess(ter))
        return ter;
    if (auto const ter = requireAuth(ctx.view, issue, dst); !isTesSuccess(ter))
        return ter;

    if (auto const err = credentials::valid(ctx.tx, ctx.view, ctx.tx[sfAccount], ctx.j);
        !isTesSuccess(err))
        return err;

    auto const transcript = sendTranscript(
        ctx.tx[sfAccount],
        dst,
        mptId,
        sleSrc->getFieldU32(sfConfidentialBalanceVersion));
    if (!sendVerify(
            makeSlice(sleSrc->getFieldVL(sfHolderEncryptionKey)),
            makeSlice(sleDst->getFieldVL(sfHolderEncryptionKey)),
            *issuerKey,
            auditorKey,
            makeSlice(sleSrc->getFieldVL(sfConfidentialBalanceSpending)),
            ctx.tx[sfSenderEncryptedAmount],
            ctx.tx[sfDestinationEncryptedAmount],
            ctx.tx[sfIssuerEncryptedAmount],
            auditorAmount,
            ctx.tx[sfAmountCommitment],
            ctx.tx[sfBalanceCommitment],
            ctx.tx[sfZKProof],
            transcript))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::doApply()
{
    auto const mptId = ctx_.tx[sfMPTokenIssuanceID];
    auto const dst = ctx_.tx[sfDestination];
    auto sleIssuance = view().peek(keylet::mptIssuance(mptId));
    auto sleSrc = view().peek(keylet::mptoken(mptId, accountID_));
    auto sleDst = view().peek(keylet::mptoken(mptId, dst));
    auto const sleDstAcct = view().read(keylet::account(dst));
    if (!sleIssuance || !sleSrc || !sleDst || !sleDstAcct)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    if (auto err = verifyDepositPreauth(
            ctx_.tx, view(), accountID_, dst, sleDstAcct, ctx_.journal);
        !isTesSuccess(err))
        return err;

    if (auto const ter = debitCiphertext(
            *sleSrc, sfConfidentialBalanceSpending, ctx_.tx[sfSenderEncryptedAmount]))
        return ter;
    if (auto const ter =
            debitCiphertext(*sleSrc, sfIssuerEncryptedBalance, ctx_.tx[sfIssuerEncryptedAmount]))
        return ter;
    if (auto const ter = creditCiphertext(
            *sleDst, sfConfidentialBalanceInbox, ctx_.tx[sfDestinationEncryptedAmount]))
        return ter;
    if (auto const ter =
            creditCiphertext(*sleDst, sfIssuerEncryptedBalance, ctx_.tx[sfIssuerEncryptedAmount]))
        return ter;

    if (auto const auditorAmount = ctx_.tx[~sfAuditorEncryptedAmount])
    {
        if (auto const ter =
                debitCiphertext(*sleSrc, sfAuditorEncryptedBalance, *auditorAmount))
            return ter;
        if (auto const ter =
                creditCiphertext(*sleDst, sfAuditorEncryptedBalance, *auditorAmount))
            return ter;
    }

    auto const version = sleSrc->getFieldU32(sfConfidentialBalanceVersion);
    sleSrc->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

    view().update(sleSrc);
    view().update(sleDst);
    return tesSUCCESS;
}

void
ConfidentialMPTSend::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTSend::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
