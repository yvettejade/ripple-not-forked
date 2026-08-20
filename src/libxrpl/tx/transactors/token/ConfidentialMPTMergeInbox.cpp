#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

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

namespace xrpl {

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const&)
{
    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) *
        static_cast<XRPAmount::value_type>(kConfidentialMptFeeMultiplier);
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
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

    if (!sleMpt->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceVersion))
        return tecNO_PERMISSION;

    MPTIssue const issue{mptId};
    if (auto const ter = requireAuth(ctx.view, issue, ctx.tx[sfAccount]); !isTesSuccess(ter))
        return ter;

    if (isFrozen(ctx.view, ctx.tx[sfAccount], issue))
        return tecLOCKED;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const mptId = ctx_.tx[sfMPTokenIssuanceID];
    auto sleIssuance = view().peek(keylet::mptIssuance(mptId));
    auto sleMpt = view().peek(keylet::mptoken(mptId, accountID_));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // getFieldVL returns Blob by value; keep bytes alive for Slice views.
    Blob const spendingBlob = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
    Blob const inboxBlob = sleMpt->getFieldVL(sfConfidentialBalanceInbox);
    Blob const holderPkBlob = sleMpt->getFieldVL(sfHolderEncryptionKey);

    auto const summed = elgamalAdd(makeSlice(spendingBlob), makeSlice(inboxBlob));
    if (!summed)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldVL(sfConfidentialBalanceSpending, *summed);

    auto const zero =
        encZero(accountID_, (*sleIssuance)[sfIssuer], mptId, makeSlice(holderPkBlob));
    if (!zero)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    sleMpt->setFieldVL(sfConfidentialBalanceInbox, *zero);

    auto const version = sleMpt->getFieldU32(sfConfidentialBalanceVersion);
    sleMpt->setFieldU32(
        sfConfidentialBalanceVersion,
        version == std::numeric_limits<std::uint32_t>::max() ? 0 : version + 1);

    view().update(sleMpt);
    return tesSUCCESS;
}

void
ConfidentialMPTMergeInbox::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
}

bool
ConfidentialMPTMergeInbox::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
