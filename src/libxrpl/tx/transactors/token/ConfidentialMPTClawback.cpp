#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>

namespace xrpl {
namespace {

[[nodiscard]] std::optional<Secp256k1Point>
parsePk(Blob const& key)
{
    return Secp256k1Point::parse(makeSlice(key));
}

[[nodiscard]] std::array<std::uint8_t, AccountID::kBytes + 4>
clawbackTxSpecific(AccountID const& holder)
{
    std::array<std::uint8_t, AccountID::kBytes + 4> out{};
    std::memcpy(out.data(), holder.data(), AccountID::kBytes);
    return out;
}

[[nodiscard]] TER
resetEncZero(
    SLE& sle,
    SF_VL const& field,
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID,
    Secp256k1Point const& pk)
{
    auto zero = encZero(account, issuer, issuanceID, pk);
    if (!zero)
        return tefINTERNAL;  // LCOV_EXCL_LINE
    sle.setFieldVL(field, *zero);
    return tesSUCCESS;
}

}  // namespace

bool
ConfidentialMPTClawback::checkExtraFeatures(PreflightContext const& ctx)
{
    return ctx.rules.enabled(featureConfidentialTransfer);
}

NotTEC
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureConfidentialTransfer))
        return temDISABLED;

    auto const& tx = ctx.tx;
    if (tx[sfAccount] == tx[sfHolder])
        return temMALFORMED;

    auto const proof = tx[sfZKProof];
    if (proof.size() != kClawbackSigmaSize)
        return temMALFORMED;

    auto const amount = tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * 10;
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const& tx = ctx.tx;
    auto const issuer = tx[sfAccount];
    auto const holder = tx[sfHolder];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    if (!ctx.view.exists(keylet::account(holder)))
        return tecNO_TARGET;

    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(issuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    // Spec 11.3.1.2 lists temMALFORMED if Account is not issuer.
    if (issuer != (*sleIssuance)[sfIssuer])
        return tecNO_PERMISSION;

    if (!sleIssuance->isFlag(lsfMPTCanClawback))
        return tecNO_PERMISSION;
    if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        return tecNO_PERMISSION;
    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const sleMpt = ctx.view.read(keylet::mptoken(issuanceID, holder));
    if (!sleMpt)
        return tecOBJECT_NOT_FOUND;

    if (!sleMpt->isFieldPresent(sfIssuerEncryptedBalance) ||
        !sleMpt->isFieldPresent(sfHolderEncryptionKey) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceSpending) ||
        !sleMpt->isFieldPresent(sfConfidentialBalanceInbox))
        return tecNO_PERMISSION;

    if ((*sleIssuance)[sfConfidentialOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;
    if ((*sleIssuance)[sfOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!issuerPk)
        return tecNO_PERMISSION;  // LCOV_EXCL_LINE

    auto const issuerCt =
        parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
    if (!issuerCt)
        return tecNO_PERMISSION;

    auto const specific = clawbackTxSpecific(holder);
    auto const ctxID = confidentialTxContextID(
        static_cast<std::uint16_t>(tx.getTxnType()),
        issuer,
        issuanceID,
        tx.getSeqProxy().value(),
        makeSlice(specific));

    if (!verifyClawbackSigma(amount, *issuerPk, *issuerCt, tx[sfZKProof], makeSlice(ctxID)))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const& tx = ctx_.tx;
    auto const issuer = tx[sfAccount];
    auto const holder = tx[sfHolder];
    auto const issuanceID = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto const sleIssuance = view().peek(keylet::mptIssuance(issuanceID));
    auto const sleMpt = view().peek(keylet::mptoken(issuanceID, holder));
    if (!sleIssuance || !sleMpt)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // xls-0096 §11 burns OA and COA; addendum §5.9 says credit issuer reserve.
    // Follow xls-0096 burn (no issuer credit).
    (*sleIssuance)[sfConfidentialOutstandingAmount] =
        (*sleIssuance)[sfConfidentialOutstandingAmount] - amount;
    (*sleIssuance)[sfOutstandingAmount] = (*sleIssuance)[sfOutstandingAmount] - amount;

    auto const holderPk = parsePk(sleMpt->getFieldVL(sfHolderEncryptionKey));
    auto const issuerPk = parsePk(sleIssuance->getFieldVL(sfIssuerEncryptionKey));
    if (!holderPk || !issuerPk)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    if (auto const ter = resetEncZero(
            *sleMpt, sfConfidentialBalanceSpending, holder, issuer, issuanceID, *holderPk))
        return ter;
    if (auto const ter = resetEncZero(
            *sleMpt, sfConfidentialBalanceInbox, holder, issuer, issuanceID, *holderPk))
        return ter;
    if (auto const ter =
            resetEncZero(*sleMpt, sfIssuerEncryptedBalance, holder, issuer, issuanceID, *issuerPk))
        return ter;
    if (sleMpt->isFieldPresent(sfAuditorEncryptedBalance))
    {
        if (!sleIssuance->isFieldPresent(sfAuditorEncryptionKey))
            return tefINTERNAL;  // LCOV_EXCL_LINE
        auto const auditorPk = parsePk(sleIssuance->getFieldVL(sfAuditorEncryptionKey));
        if (!auditorPk)
            return tefINTERNAL;  // LCOV_EXCL_LINE
        if (auto const ter = resetEncZero(
                *sleMpt, sfAuditorEncryptedBalance, holder, issuer, issuanceID, *auditorPk))
            return ter;
    }

    auto const version = (*sleMpt)[~sfConfidentialBalanceVersion].valueOr(0);
    (*sleMpt)[sfConfidentialBalanceVersion] = version + 1;

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
