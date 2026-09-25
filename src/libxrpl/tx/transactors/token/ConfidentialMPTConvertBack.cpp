#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/Bulletproof.h>
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

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace xrpl {

using namespace confidential;
namespace cm = confidential_mpt;

namespace {

// Updated spec section 4.12: pi_bal (128 bytes) || single Bulletproof (688).
constexpr std::size_t kProofLength = kConvertBackSigmaProofLength + kSingleRangeProofLength;

}  // namespace

XRPAmount
ConfidentialMPTConvertBack::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cm::baseFee(view, tx);
}

NotTEC
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    auto const& tx = ctx.tx;

    if (MPTIssue{tx[sfMPTokenIssuanceID]}.getIssuer() == tx[sfAccount])
        return temMALFORMED;

    if (!cm::blindingFactor(tx))
        return temMALFORMED;

    if (auto const ter = cm::checkCiphertexts(
            tx, {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount, &sfAuditorEncryptedAmount});
        !isTesSuccess(ter))
        return ter;

    // XLS-0096 section 10.4.1 lists no code for these; updated spec section
    // 4.8 requires a well-formed commitment.
    if (!cm::point(tx, sfBalanceCommitment) || tx.getFieldVL(sfZKProof).size() != kProofLength)
        return temMALFORMED;

    auto const amount = tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
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
    if (!keys || !cm::isInitialized(*mptoken))
        return tecNO_PERMISSION;

    if (auto const ter = cm::checkAuditorPolicy(tx, *keys); !isTesSuccess(ter))
        return ter;

    MPTIssue const mptIssue{id};
    if (auto const ter = requireAuth(ctx.view, mptIssue, account); !isTesSuccess(ter))
        return ter;

    // Before any proof, so a frozen holder's retries cost nothing.
    if (isFrozen(ctx.view, account, mptIssue))
        return terFROZEN;

    auto const amount = tx[sfMPTAmount];
    if ((*issuance)[sfConfidentialOutstandingAmount] < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const holderKey = cm::point(*mptoken, sfHolderEncryptionKey);
    auto const spending = cm::ciphertext(*mptoken, sfConfidentialBalanceSpending);
    if (!holderKey || !spending)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    // Updated spec section 4.3: the disclosed blinding factor must reproduce
    // every ciphertext for the revealed amount.
    auto const m = Scalar::fromUint64(amount);
    auto const r = *cm::blindingFactor(tx);
    if (!verifyElGamalEncryption(*cm::ciphertext(tx, sfHolderEncryptedAmount), m, r, *holderKey) ||
        !verifyElGamalEncryption(
            *cm::ciphertext(tx, sfIssuerEncryptedAmount), m, r, keys->issuer) ||
        (keys->auditor &&
         !verifyElGamalEncryption(
             *cm::ciphertext(tx, sfAuditorEncryptedAmount), m, r, *keys->auditor)))
        return tecBAD_PROOF;

    // Sections 4.5-4.7: PC_b opens to the spending balance, and
    // PC_rem = PC_b - m·G opens to a value in [0, 2^64), both bound to the
    // spending balance version.
    auto const contextID =
        cm::contextID(tx, account, mptoken->getFieldU32(sfConfidentialBalanceVersion));
    auto const commitment = *cm::point(tx, sfBalanceCommitment);
    Blob const proof = tx.getFieldVL(sfZKProof);
    Slice const sigma(proof.data(), kConvertBackSigmaProofLength);
    Slice const range(proof.data() + kConvertBackSigmaProofLength, kSingleRangeProofLength);
    if (!verifyBalance(
            {.key = *holderKey, .balance = *spending, .balanceCommitment = commitment},
            sigma,
            contextID))
        return tecBAD_PROOF;
    std::array<Point, 1> const remainder{commitment - mulGenerator(m)};
    if (!verifyRange(remainder, range, contextID))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const& tx = ctx_.tx;
    auto const id = tx[sfMPTokenIssuanceID];
    auto const amount = tx[sfMPTAmount];

    auto issuance = view().peek(keylet::mptIssuance(id));
    auto mptoken = view().peek(keylet::mptoken(id, accountID_));
    if (!issuance || !mptoken)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // Section 10.5 and updated spec eq. (42)-(45). Section 10.5 omits the
    // auditor mirror; it is debited like the issuer mirror so it keeps
    // encrypting the same balance. OutstandingAmount is unchanged (sections
    // 10.2 and 10.5; the section 10.7 example's "OA decreases" contradicts
    // them and the updated spec).
    if (auto const ter = cm::debit(
            *mptoken, sfConfidentialBalanceSpending, *cm::ciphertext(tx, sfHolderEncryptedAmount));
        !isTesSuccess(ter))
        return ter;
    if (auto const ter = cm::debit(
            *mptoken, sfIssuerEncryptedBalance, *cm::ciphertext(tx, sfIssuerEncryptedAmount));
        !isTesSuccess(ter))
        return ter;
    if (tx.isFieldPresent(sfAuditorEncryptedAmount))
    {
        if (auto const ter = cm::debit(
                *mptoken, sfAuditorEncryptedBalance, *cm::ciphertext(tx, sfAuditorEncryptedAmount));
            !isTesSuccess(ter))
            return ter;
    }
    mptoken->setFieldU32(
        sfConfidentialBalanceVersion,
        static_cast<std::uint32_t>(mptoken->getFieldU32(sfConfidentialBalanceVersion) + 1));

    (*mptoken)[sfMPTAmount] = (*mptoken)[sfMPTAmount] + amount;
    (*issuance)[sfConfidentialOutstandingAmount] =
        (*issuance)[sfConfidentialOutstandingAmount] - amount;
    view().update(mptoken);
    view().update(issuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvertBack::visitInvariantEntry(
    bool,
    std::shared_ptr<SLE const> const&,
    std::shared_ptr<SLE const> const&)
{
    // ValidConfidentialMPToken checks this transaction's supply change.
}

bool
ConfidentialMPTConvertBack::finalizeInvariants(
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
