#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/ConfidentialProofs.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTHelpers.h>

#include <cstdint>
#include <memory>

namespace xrpl {

using namespace confidential;
namespace cm = confidential_mpt;

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cm::baseFee(view, tx);
}

NotTEC
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    auto const& tx = ctx.tx;

    // XLS-0096 section 11.3.1.
    if (MPTIssue{tx[sfMPTokenIssuanceID]}.getIssuer() != tx[sfAccount] ||
        tx[sfAccount] == tx[sfHolder] || tx.getFieldVL(sfZKProof).size() != kClawbackProofLength)
        return temMALFORMED;

    auto const amount = tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const holder = tx[sfHolder];
    auto const id = tx[sfMPTokenIssuanceID];

    // Section 11.3.2, in order. The issuer may claw back from a locked or
    // unauthorized holder.
    if (!ctx.view.exists(keylet::account(holder)))
        return tecNO_TARGET;

    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const mptoken = ctx.view.read(keylet::mptoken(id, holder));
    if (!issuance || !mptoken)
        return tecOBJECT_NOT_FOUND;

    if (!issuance->isFlag(lsfMPTCanClawback))
        return tecNO_PERMISSION;

    auto const issuerKey = cm::point(*issuance, sfIssuerEncryptionKey);
    auto const mirror = cm::ciphertext(*mptoken, sfIssuerEncryptedBalance);
    if (!issuerKey || !mirror)
        return tecNO_PERMISSION;

    auto const amount = tx[sfMPTAmount];
    if ((*issuance)[sfConfidentialOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    // Updated spec sections 5.4-5.6: the issuer mirror encrypts exactly the
    // amount, proved with the issuer key and bound to Holder || 0, not the
    // version, so the holder cannot invalidate a prepared clawback.
    if (!verifyClawback(
            *issuerKey,
            *mirror,
            Scalar::fromUint64(amount),
            makeSlice(tx.getFieldVL(sfZKProof)),
            cm::contextID(tx, holder, 0)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const& tx = ctx_.tx;
    auto const id = tx[sfMPTokenIssuanceID];
    auto const holder = tx[sfHolder];
    auto const amount = tx[sfMPTAmount];

    auto issuance = view().peek(keylet::mptIssuance(id));
    auto mptoken = view().peek(keylet::mptoken(id, holder));
    if (!issuance || !mptoken)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    auto const keys = cm::issuanceKeys(*issuance);
    auto const holderKey = cm::point(*mptoken, sfHolderEncryptionKey);
    if (!keys || !holderKey)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // Section 11.4 and updated spec eq. (63)-(68): every balance becomes the
    // canonical encrypted zero, the version advances and the amount leaves
    // circulation (the "issuer's public reserve" of updated spec section 5.9
    // is its unissued supply).
    auto const reset = [&](SF_VL const& field, Point const& pk) {
        return cm::store(*mptoken, field, encryptedZero(holder, id, pk));
    };
    if (auto const ter = reset(sfConfidentialBalanceSpending, *holderKey); !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE
    if (auto const ter = reset(sfConfidentialBalanceInbox, *holderKey); !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE
    if (auto const ter = reset(sfIssuerEncryptedBalance, keys->issuer); !isTesSuccess(ter))
        return ter;  // LCOV_EXCL_LINE
    if (keys->auditor)
    {
        if (auto const ter = reset(sfAuditorEncryptedBalance, *keys->auditor); !isTesSuccess(ter))
            return ter;  // LCOV_EXCL_LINE
    }
    cm::advanceVersion(*mptoken);

    (*issuance)[sfConfidentialOutstandingAmount] =
        (*issuance)[sfConfidentialOutstandingAmount] - amount;
    (*issuance)[sfOutstandingAmount] = (*issuance)[sfOutstandingAmount] - amount;
    view().update(mptoken);
    view().update(issuance);
    return tesSUCCESS;
}

void
ConfidentialMPTClawback::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
    // ValidConfidentialMPToken checks this transaction's state changes.
}

bool
ConfidentialMPTClawback::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // ValidConfidentialMPToken checks this transaction's state changes.
    return true;
}

}  // namespace xrpl
