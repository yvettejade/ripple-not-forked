#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
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
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cm::baseFee(view, tx);
}

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    auto const& tx = ctx.tx;

    // Only holders convert; the issuance ID encodes the issuer.
    if (MPTIssue{tx[sfMPTokenIssuanceID]}.getIssuer() == tx[sfAccount])
        return temMALFORMED;

    // The proof of knowledge accompanies exactly the key it registers.
    bool const hasKey = tx.isFieldPresent(sfHolderEncryptionKey);
    if (hasKey != tx.isFieldPresent(sfZKProof))
        return temMALFORMED;

    // XLS-0096 only requires 33 bytes; an invalid point could never verify
    // the proof of knowledge, so reject it as malformed up front.
    if (hasKey && !cm::point(tx, sfHolderEncryptionKey))
        return temMALFORMED;

    // sfBlindingFactor is a UINT256, so it is always 32 bytes; it must also
    // be a canonical scalar.
    if (!cm::blindingFactor(tx))
        return temMALFORMED;

    if (hasKey && tx.getFieldVL(sfZKProof).size() != kSchnorrProofLength)
        return temMALFORMED;

    if (auto const ter = cm::checkCiphertexts(
            tx, {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount, &sfAuditorEncryptedAmount});
        !isTesSuccess(ter))
        return ter;

    if (tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

NotTEC
ConfidentialMPTConvert::checkPermission(ReadView const& view, STTx const& tx)
{
    // The registered key can never change and controls the confidential
    // balance, so only the holder may choose it (XLS-0096 section 5.5 trusts
    // delegates to operate an account, not to take it over).
    if (tx.isFieldPresent(sfDelegate) && tx.isFieldPresent(sfHolderEncryptionKey))
        return terNO_DELEGATE_PERMISSION;
    return Transactor::checkPermission(view, tx);
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const account = tx[sfAccount];
    auto const id = tx[sfMPTokenIssuanceID];

    auto const issuance = ctx.view.read(keylet::mptIssuance(id));
    auto const mptoken = ctx.view.read(keylet::mptoken(id, account));
    if (!issuance || !mptoken)
        return tecOBJECT_NOT_FOUND;

    if (!issuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;

    auto const keys = cm::issuanceKeys(*issuance);
    if (!keys)
        return tecNO_PERMISSION;

    if (auto const ter = cm::checkAuditorPolicy(tx, *keys); !isTesSuccess(ter))
        return ter;

    bool const registering = tx.isFieldPresent(sfHolderEncryptionKey);
    if (registering && mptoken->isFieldPresent(sfHolderEncryptionKey))
        return tecDUPLICATE;
    if (!registering && !mptoken->isFieldPresent(sfHolderEncryptionKey))
        return tecNO_PERMISSION;

    MPTIssue const mptIssue{id};
    if (auto const ter = requireAuth(ctx.view, mptIssue, account); !isTesSuccess(ter))
        return ter;

    // XLS-0096 lists no freeze rule for Convert; locked funds must not move,
    // and converting would change the mirror an issuer's clawback proof uses.
    if (isFrozen(ctx.view, account, mptIssue))
        return tecLOCKED;

    auto const amount = tx[sfMPTAmount];
    if (amount > (*mptoken)[sfMPTAmount])
        return tecINSUFFICIENT_FUNDS;

    auto const holderKey = registering ? cm::point(tx, sfHolderEncryptionKey)
                                       : cm::point(*mptoken, sfHolderEncryptionKey);
    if (!holderKey)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // Section 2.3: the disclosed blinding factor must reproduce every
    // ciphertext for the revealed amount.
    auto const m = Scalar::fromUint64(amount);
    auto const r = *cm::blindingFactor(tx);
    if (!verifyElGamalEncryption(*cm::ciphertext(tx, sfHolderEncryptedAmount), m, r, *holderKey) ||
        !verifyElGamalEncryption(
            *cm::ciphertext(tx, sfIssuerEncryptedAmount), m, r, keys->issuer) ||
        (keys->auditor &&
         !verifyElGamalEncryption(
             *cm::ciphertext(tx, sfAuditorEncryptedAmount), m, r, *keys->auditor)))
        return tecBAD_PROOF;

    if (registering &&
        !verifyKnowledge(
            *holderKey, makeSlice(tx.getFieldVL(sfZKProof)), cm::contextID(tx, account, 0)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const& tx = ctx_.tx;
    auto const id = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto issuance = view().peek(keylet::mptIssuance(id));
    auto mptoken = view().peek(keylet::mptoken(id, accountID_));
    if (!issuance || !mptoken)
        return tecINTERNAL;  // LCOV_EXCL_LINE
    auto const keys = cm::issuanceKeys(*issuance);
    if (!keys)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // Section 7.5: initialize on first use with the canonical encrypted
    // zeros and version 0, then credit the inbox and the mirrors.
    if (tx.isFieldPresent(sfHolderEncryptionKey))
    {
        auto const holderKey = *cm::point(tx, sfHolderEncryptionKey);
        mptoken->setFieldVL(sfHolderEncryptionKey, tx.getFieldVL(sfHolderEncryptionKey));
        auto const holderZero = encryptedZero(accountID_, id, holderKey);
        if (auto const ter = cm::store(*mptoken, sfConfidentialBalanceSpending, holderZero);
            !isTesSuccess(ter))
            return ter;  // LCOV_EXCL_LINE
        if (auto const ter = cm::store(*mptoken, sfConfidentialBalanceInbox, holderZero);
            !isTesSuccess(ter))
            return ter;  // LCOV_EXCL_LINE
        if (auto const ter = cm::store(
                *mptoken, sfIssuerEncryptedBalance, encryptedZero(accountID_, id, keys->issuer));
            !isTesSuccess(ter))
            return ter;  // LCOV_EXCL_LINE
        if (keys->auditor)
        {
            if (auto const ter = cm::store(
                    *mptoken,
                    sfAuditorEncryptedBalance,
                    encryptedZero(accountID_, id, *keys->auditor));
                !isTesSuccess(ter))
                return ter;  // LCOV_EXCL_LINE
        }
        mptoken->setFieldU32(sfConfidentialBalanceVersion, 0);
    }

    // A holder who knows a balance's randomness (EncZero's is public) or the
    // key it is encrypted under can pick a blinding factor that cancels C1
    // or C2; such results cannot be stored.
    auto const credit = [&](SF_VL const& balance, SF_VL const& amountField) -> TER {
        auto const current = cm::ciphertext(*mptoken, balance);
        if (!current)
            return tecINTERNAL;  // LCOV_EXCL_LINE
        return cm::store(*mptoken, balance, *current + *cm::ciphertext(tx, amountField));
    };
    if (auto const ter = credit(sfConfidentialBalanceInbox, sfHolderEncryptedAmount);
        !isTesSuccess(ter))
        return ter;
    if (auto const ter = credit(sfIssuerEncryptedBalance, sfIssuerEncryptedAmount);
        !isTesSuccess(ter))
        return ter;
    if (keys->auditor)
    {
        if (auto const ter = credit(sfAuditorEncryptedBalance, sfAuditorEncryptedAmount);
            !isTesSuccess(ter))
            return ter;
    }

    (*mptoken)[sfMPTAmount] = (*mptoken)[sfMPTAmount] - amount;
    (*issuance)[sfConfidentialOutstandingAmount] =
        (*issuance)[sfConfidentialOutstandingAmount] + amount;
    view().update(mptoken);
    view().update(issuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvert::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
    // ValidConfidentialMPToken checks this transaction's supply change.
}

bool
ConfidentialMPTConvert::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // ValidConfidentialMPToken checks this transaction's supply change.
    return true;
}

}  // namespace xrpl
