#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

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
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <memory>

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

}  // namespace

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    auto const holderKey = ctx.tx[~sfHolderEncryptionKey];
    auto const zkProof = ctx.tx[~sfZKProof];
    if (static_cast<bool>(holderKey) != static_cast<bool>(zkProof))
        return temMALFORMED;

    if (holderKey && !isConfidentialPubKey(*holderKey))
        return temMALFORMED;

    if (zkProof && zkProof->size() != kConfidentialSchnorrProofLength)
        return temMALFORMED;

    auto const amount = ctx.tx[sfMPTAmount];
    if (amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    if (!isConfidentialCiphertext(ctx.tx[sfHolderEncryptedAmount]) ||
        !isConfidentialCiphertext(ctx.tx[sfIssuerEncryptedAmount]))
        return temBAD_CIPHERTEXT;

    if (auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
        auditorAmount && !isConfidentialCiphertext(*auditorAmount))
        return temBAD_CIPHERTEXT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) *
        static_cast<XRPAmount::value_type>(kConfidentialMptFeeMultiplier);
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
{
    auto const mptId = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptId));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    auto const issuerKey = (*sleIssuance)[~sfIssuerEncryptionKey];
    if (!issuerKey)
        return tecNO_PERMISSION;

    if (ctx.tx[sfAccount] == (*sleIssuance)[sfIssuer])
        return temMALFORMED;

    auto const sleMpt = ctx.view.read(keylet::mptoken(mptId, ctx.tx[sfAccount]));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    auto const amount = ctx.tx[sfMPTAmount];
    if ((*sleMpt)[sfMPTAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const holderKey = ctx.tx[~sfHolderEncryptionKey];
    if (holderKey && sleMpt->isFieldPresent(sfHolderEncryptionKey))
        return tecDUPLICATE;
    if (!holderKey && !sleMpt->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    auto const pkHolder =
        holderKey ? *holderKey : makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey));

    auto const r = ctx.tx[sfBlindingFactor];
    if (!elgamalMatches(ctx.tx[sfHolderEncryptedAmount], pkHolder, amount, r) ||
        !elgamalMatches(ctx.tx[sfIssuerEncryptedAmount], *issuerKey, amount, r))
        return tecBAD_PROOF;

    auto const auditorKey = (*sleIssuance)[~sfAuditorEncryptionKey];
    auto const auditorAmount = ctx.tx[~sfAuditorEncryptedAmount];
    if (static_cast<bool>(auditorKey) != static_cast<bool>(auditorAmount))
        return tecNO_PERMISSION;
    if (auditorKey &&
        !elgamalMatches(*auditorAmount, *auditorKey, amount, r))
        return tecBAD_PROOF;

    if (holderKey)
    {
        auto const proof = ctx.tx[sfZKProof];
        auto const transcript = convertSchnorrTranscript(ctx.tx[sfAccount], mptId);
        if (!schnorrVerify(*holderKey, proof, transcript))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const mptId = ctx_.tx[sfMPTokenIssuanceID];
    auto const amount = ctx_.tx[sfMPTAmount];
    auto sleIssuance = view().peek(keylet::mptIssuance(mptId));
    auto sleMpt = view().peek(keylet::mptoken(mptId, accountID_));
    if (!sleIssuance || !sleMpt)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    sleMpt->setFieldU64(sfMPTAmount, (*sleMpt)[sfMPTAmount] - amount);

    auto const coa = (*sleIssuance)[~sfConfidentialOutstandingAmount].valueOr(0);
    sleIssuance->setFieldU64(sfConfidentialOutstandingAmount, coa + amount);

    if (auto const holderKey = ctx_.tx[~sfHolderEncryptionKey])
        sleMpt->setFieldVL(sfHolderEncryptionKey, *holderKey);

    auto const initializing = !sleMpt->isFieldPresent(sfConfidentialBalanceSpending);
    if (initializing)
    {
        auto const zero = encZero(
            accountID_,
            (*sleIssuance)[sfIssuer],
            mptId,
            makeSlice(sleMpt->getFieldVL(sfHolderEncryptionKey)));
        if (!zero)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        sleMpt->setFieldVL(sfConfidentialBalanceSpending, *zero);
        sleMpt->setFieldU32(sfConfidentialBalanceVersion, 0);
    }

    if (auto const ter =
            creditCiphertext(*sleMpt, sfConfidentialBalanceInbox, ctx_.tx[sfHolderEncryptedAmount]))
        return ter;
    if (auto const ter =
            creditCiphertext(*sleMpt, sfIssuerEncryptedBalance, ctx_.tx[sfIssuerEncryptedAmount]))
        return ter;
    if (auto const auditorAmount = ctx_.tx[~sfAuditorEncryptedAmount])
    {
        if (auto const ter =
                creditCiphertext(*sleMpt, sfAuditorEncryptedBalance, *auditorAmount))
            return ter;
    }

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
