#include <xrpl/tx/invariants/MPTInvariant.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/beast/utility/Journal.h>
#include <xrpl/beast/utility/instrumentation.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/Rules.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/invariants/InvariantCheckPrivilege.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTHelpers.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace xrpl {

void
ValidMPTIssuance::visitEntry(
    bool isDelete,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    // The sfReferenceHolding tracking and the deleted-holding capture are
    // only meaningful post-fixCleanup3_2_0 (the field is never set
    // pre-amendment, and the holding-deletion rule does not apply).
    // Skip both blocks when the amendment is off so we avoid wasted work
    // on the hot path.
    bool const fix320Enabled = isFeatureEnabled(fixCleanup3_2_0);

    if (after && after->getType() == ltMPTOKEN_ISSUANCE)
    {
        if (isDelete)
        {
            mptIssuancesDeleted_++;
        }
        else if (!before)
        {
            mptIssuancesCreated_++;
            if (fix320Enabled && after->isFieldPresent(sfReferenceHolding))
                referenceHoldingSetOnCreate_ = true;
        }
        else if (fix320Enabled)
        {
            // Modified issuance: detect any change to sfReferenceHolding.
            bool const beforePresent = before->isFieldPresent(sfReferenceHolding);
            bool const afterPresent = after->isFieldPresent(sfReferenceHolding);
            if (beforePresent != afterPresent ||
                (afterPresent &&
                 before->getFieldH256(sfReferenceHolding) !=
                     after->getFieldH256(sfReferenceHolding)))
            {
                referenceHoldingMutated_ = true;
            }
        }
    }

    if (after && after->getType() == ltMPTOKEN)
    {
        if (isDelete)
        {
            mptokensDeleted_++;
            if (fix320Enabled)
                deletedHoldings_.push_back(after);
        }
        else if (!before)
        {
            mptokensCreated_++;
            MPTIssue const mptIssue{after->at(sfMPTokenIssuanceID)};
            if (mptIssue.getIssuer() == after->at(sfAccount))
                mptCreatedByIssuer_ = true;
        }
    }

    // Capture deleted RippleState SLEs so finalize() can verify none of
    // them were owned by a vault pseudo-account outside VaultDelete.
    if (fix320Enabled && isDelete && after && after->getType() == ltRIPPLE_STATE)
        deletedHoldings_.push_back(after);
}

bool
ValidMPTIssuance::finalize(
    STTx const& tx,
    TER const result,
    XRPAmount const fee,
    ReadView const& view,
    beast::Journal const& j) const
{
    auto const& rules = view.rules();
    bool const mptV2Enabled = rules.enabled(featureMPTokensV2);

    // Post-fixCleanup3_2_0:
    //   - sfReferenceHolding is set only by VaultCreate at share-issuance
    //     creation, and is immutable thereafter.
    //   - A vault pseudo-account's MPToken or RippleState may only be
    //     deleted by VaultDelete; the share's sfReferenceHolding pointer
    //     must not dangle outside that controlled lifecycle.
    if (rules.enabled(fixCleanup3_2_0))
    {
        bool invariantPasses = true;
        if (referenceHoldingMutated_)
        {
            JLOG(j.fatal()) << "Invariant failed: sfReferenceHolding was modified "
                               "on an existing MPTokenIssuance";
            invariantPasses = false;
        }
        if (referenceHoldingSetOnCreate_ && tx.getTxnType() != ttVAULT_CREATE)
        {
            JLOG(j.fatal()) << "Invariant failed: sfReferenceHolding set on a new "
                               "MPTokenIssuance by a non-VaultCreate transaction";
            invariantPasses = false;
        }
        if (!deletedHoldings_.empty() && tx.getTxnType() != ttVAULT_DELETE)
        {
            auto const isVaultPseudo = [&](AccountID const& acct) {
                auto const sle = view.read(keylet::account(acct));
                return sle && sle->isFieldPresent(sfVaultID);
            };
            for (auto const& sleHolding : deletedHoldings_)
            {
                bool offending = false;
                if (sleHolding->getType() == ltMPTOKEN)
                {
                    offending = isVaultPseudo(sleHolding->at(sfAccount));
                }
                else  // ltRIPPLE_STATE
                {
                    auto const lowLimit = sleHolding->getFieldAmount(sfLowLimit);
                    auto const highLimit = sleHolding->getFieldAmount(sfHighLimit);
                    // Each limit's STAmount.issuer is the COUNTERPARTY of
                    // that side's owner: lowLimit's issuer is the high
                    // account, highLimit's issuer is the low account.
                    offending =
                        isVaultPseudo(lowLimit.getIssuer()) || isVaultPseudo(highLimit.getIssuer());
                }
                if (offending)
                {
                    JLOG(j.fatal()) << "Invariant failed: vault pseudo-account holding "
                                       "deleted by a non-VaultDelete transaction";
                    invariantPasses = false;
                }
            }
        }
        if (!invariantPasses)
            return false;
    }

    if (isTesSuccess(result) || (mptV2Enabled && result == tecINCOMPLETE))
    {
        [[maybe_unused]]
        bool const enforceCreatedByIssuer =
            rules.enabled(featureSingleAssetVault) || rules.enabled(featureLendingProtocol);
        if (mptCreatedByIssuer_)
        {
            JLOG(j.fatal()) << "Invariant failed: MPToken created for the MPT issuer";
            // The comment above starting with "assert(enforce)" explains this
            // assert.
            XRPL_ASSERT_PARTS(
                enforceCreatedByIssuer, "xrpl::ValidMPTIssuance::finalize", "no issuer MPToken");
            if (enforceCreatedByIssuer)
                return false;
        }

        auto const txnType = tx.getTxnType();
        if (hasPrivilege(tx, CreateMptIssuance))
        {
            if (mptIssuancesCreated_ == 0)
            {
                JLOG(j.fatal()) << "Invariant failed: transaction "
                                   "succeeded without creating a MPT issuance";
            }
            else if (mptIssuancesDeleted_ != 0)
            {
                JLOG(j.fatal()) << "Invariant failed: transaction "
                                   "succeeded while removing MPT issuances";
            }
            else if (mptIssuancesCreated_ > 1)
            {
                JLOG(j.fatal()) << "Invariant failed: transaction "
                                   "succeeded but created multiple issuances";
            }

            return mptIssuancesCreated_ == 1 && mptIssuancesDeleted_ == 0;
        }

        if (hasPrivilege(tx, DestroyMptIssuance))
        {
            if (mptIssuancesDeleted_ == 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT issuance deletion "
                                   "succeeded without removing a MPT issuance";
            }
            else if (mptIssuancesCreated_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT issuance deletion "
                                   "succeeded while creating MPT issuances";
            }
            else if (mptIssuancesDeleted_ > 1)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT issuance deletion "
                                   "succeeded but deleted multiple issuances";
            }

            return mptIssuancesCreated_ == 0 && mptIssuancesDeleted_ == 1;
        }

        bool const lendingProtocolEnabled = rules.enabled(featureLendingProtocol);
        // ttESCROW_FINISH may authorize an MPT, but it can't have the
        // mayAuthorizeMPT privilege, because that may cause
        // non-amendment-gated side effects.
        bool const enforceEscrowFinish = (txnType == ttESCROW_FINISH) &&
            (rules.enabled(featureSingleAssetVault) || lendingProtocolEnabled);
        if (hasPrivilege(tx, MustAuthorizeMpt | MayAuthorizeMpt) || enforceEscrowFinish)
        {
            bool const submittedByIssuer = tx.isFieldPresent(sfHolder);

            if (mptIssuancesCreated_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but created MPT issuances";
                return false;
            }
            if (mptIssuancesDeleted_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but deleted issuances";
                return false;
            }
            if (mptV2Enabled && hasPrivilege(tx, MayAuthorizeMpt) &&
                (txnType == ttAMM_WITHDRAW || txnType == ttAMM_CLAWBACK))
            {
                if (submittedByIssuer && txnType == ttAMM_WITHDRAW && mptokensCreated_ > 0)
                {
                    JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                       "submitted by issuer succeeded "
                                       "but created bad number of mptokens";
                    return false;
                }
                //  At most one MPToken may be created on withdraw/clawback since:
                //  - Liquidity Provider must have at least one token in order
                //    participate in AMM pool liquidity.
                //  - At most two MPTokens may be deleted if AMM pool, which has exactly
                //    two tokens, is empty after withdraw/clawback.
                if (mptokensCreated_ > 1 || mptokensDeleted_ > 2)
                {
                    JLOG(j.fatal()) << "Invariant failed: MPT authorize  succeeded "
                                       "but created/deleted bad number of mptokens";
                    return false;
                }
            }
            else if (lendingProtocolEnabled && (mptokensCreated_ + mptokensDeleted_) > 1)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize succeeded "
                                   "but created/deleted bad number mptokens";
                return false;
            }
            else if (submittedByIssuer && (mptokensCreated_ > 0 || mptokensDeleted_ > 0))
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize submitted by issuer "
                                   "succeeded but created/deleted mptokens";
                return false;
            }
            else if (
                !submittedByIssuer && hasPrivilege(tx, MustAuthorizeMpt) &&
                (mptokensCreated_ + mptokensDeleted_ != 1))
            {
                // if the holder submitted this tx, then a mptoken must be
                // either created or deleted.
                JLOG(j.fatal()) << "Invariant failed: MPT authorize submitted by holder "
                                   "succeeded but created/deleted bad number of mptokens";
                return false;
            }

            return true;
        }

        if (hasPrivilege(tx, MayCreateMpt))
        {
            bool const submittedByIssuer = tx.isFieldPresent(sfHolder);

            if (mptIssuancesCreated_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but created MPT issuances";
                return false;
            }
            if (mptIssuancesDeleted_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but deleted issuances";
                return false;
            }
            if (mptokensDeleted_ > 0)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but deleted MPTokens";
                return false;
            }
            // AMMCreate may auto-create up to two MPT objects:
            //   - one per asset side in an MPT/MPT AMM, or one in an IOU/MPT AMM.
            // CheckCash may auto-create at most one MPT object for the receiver.
            if ((txnType == ttAMM_CREATE && mptokensCreated_ > 2) ||
                (txnType == ttCHECK_CASH && mptokensCreated_ > 1))
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize "
                                   "succeeded but created bad number of mptokens";
                return false;
            }
            if (submittedByIssuer)
            {
                JLOG(j.fatal()) << "Invariant failed: MPT authorize submitted by issuer "
                                   "succeeded but created mptokens";
                return false;
            }

            // Offer crossing or payment may consume multiple offers
            // where takerPays is MPT amount. If the offer owner doesn't
            // own MPT then MPT is created automatically.
            return true;
        }

        if (txnType == ttESCROW_FINISH)
        {
            // ttESCROW_FINISH may authorize an MPT, but it can't have the
            // mayAuthorizeMPT privilege, because that may cause
            // non-amendment-gated side effects.
            XRPL_ASSERT_PARTS(
                !enforceEscrowFinish, "xrpl::ValidMPTIssuance::finalize", "not escrow finish tx");
            return true;
        }

        if (hasPrivilege(tx, MayDeleteMpt) &&
            ((txnType == ttAMM_DELETE && mptokensDeleted_ <= 2) || mptokensDeleted_ == 1) &&
            mptokensCreated_ == 0 && mptIssuancesCreated_ == 0 && mptIssuancesDeleted_ == 0)
            return true;
    }

    if (mptIssuancesCreated_ != 0)
    {
        JLOG(j.fatal()) << "Invariant failed: a MPT issuance was created";
    }
    else if (mptIssuancesDeleted_ != 0)
    {
        JLOG(j.fatal()) << "Invariant failed: a MPT issuance was deleted";
    }
    else if (mptokensCreated_ != 0)
    {
        JLOG(j.fatal()) << "Invariant failed: a MPToken was created";
    }
    else if (mptokensDeleted_ != 0)
    {
        JLOG(j.fatal()) << "Invariant failed: a MPToken was deleted";
    }

    return mptIssuancesCreated_ == 0 && mptIssuancesDeleted_ == 0 && mptokensCreated_ == 0 &&
        mptokensDeleted_ == 0;
}

namespace {

// Every MPToken field that XLS-0096 initializes; none may be removed later.
// ConfidentialBalanceVersion is not among them: it is a default field, absent
// whenever it is 0.
constexpr std::array<SField const*, 5> kConfidentialMPTokenFields{
    &sfHolderEncryptionKey,
    &sfConfidentialBalanceSpending,
    &sfConfidentialBalanceInbox,
    &sfIssuerEncryptedBalance,
    &sfAuditorEncryptedBalance};

std::uint32_t
versionOf(SLE const* sle)
{
    return sle ? (*sle)[sfConfidentialBalanceVersion] : 0;
}

bool
hasEncryptedBalance(SLE const& sle)
{
    return sle.isFieldPresent(sfConfidentialBalanceSpending) ||
        sle.isFieldPresent(sfConfidentialBalanceInbox) ||
        sle.isFieldPresent(sfIssuerEncryptedBalance) ||
        sle.isFieldPresent(sfAuditorEncryptedBalance);
}

bool
hasConfidentialState(SLE const& sle)
{
    return versionOf(&sle) != 0 ||
        std::ranges::any_of(
               kConfidentialMPTokenFields, [&](SField const* f) { return sle.isFieldPresent(*f); });
}

bool
validKeyField(SLE const& sle, SField const& field)
{
    return !sle.isFieldPresent(field) ||
        confidential::isValidPoint(makeSlice(sle.getFieldVL(field)));
}

bool
validCiphertextField(SLE const& sle, SField const& field)
{
    return !sle.isFieldPresent(field) ||
        confidential::ElGamalCiphertext::fromBytes(makeSlice(sle.getFieldVL(field))).has_value();
}

// True if any confidential MPToken field differs between the two states.
bool
confidentialFieldsDiffer(SLE const* before, SLE const* after)
{
    return versionOf(before) != versionOf(after) ||
        std::ranges::any_of(kConfidentialMPTokenFields, [&](SField const* f) {
        auto const* b = before && before->isFieldPresent(*f) ? before->peekAtPField(*f) : nullptr;
        auto const* a = after && after->isFieldPresent(*f) ? after->peekAtPField(*f) : nullptr;
        if (!a || !b)
            return a != b;
        return !a->isEquivalent(*b);
    });
}

bool
blobChanged(SLE const& before, SLE const& after, SField const& field)
{
    return before.isFieldPresent(field) &&
        (!after.isFieldPresent(field) || before.getFieldVL(field) != after.getFieldVL(field));
}

// A missing state counts as zero. nullopt if either value is out of range;
// ValidMPTPayment reports those.
std::optional<std::int64_t>
amountDelta(SLE const* before, SLE const* after, SF_UINT64 const& field)
{
    std::uint64_t const b = before ? (*before)[field] : 0;
    std::uint64_t const a = after ? (*after)[field] : 0;
    if (a > kMaxMpTokenAmount || b > kMaxMpTokenAmount)
        return std::nullopt;
    return static_cast<std::int64_t>(a) - static_cast<std::int64_t>(b);
}

std::optional<confidential::ElGamalCiphertext>
ciphertextField(STObject const& object, SF_VL const& field)
{
    return confidential::ElGamalCiphertext::fromBytes(makeSlice(object.getFieldVL(field)));
}

std::optional<confidential::Point>
pointField(STObject const& object, SF_VL const& field)
{
    return confidential::Point::fromBytes(makeSlice(object.getFieldVL(field)));
}

bool
sameField(SLE const& before, SLE const& after, SField const& field)
{
    auto const* b = before.isFieldPresent(field) ? before.peekAtPField(field) : nullptr;
    auto const* a = after.isFieldPresent(field) ? after.peekAtPField(field) : nullptr;
    return (!a && !b) || (a && b && a->isEquivalent(*b));
}

// The transaction's ciphertext in `amount` encrypts MPTAmount under pk with
// the disclosed BlindingFactor (XLS-0096 §7.2, §10.3).
bool
disclosed(STTx const& tx, SF_VL const& amount, confidential::Point const& pk)
{
    auto const ct = ciphertextField(tx, amount);
    auto const bf = tx[sfBlindingFactor];
    auto const r = confidential::Scalar::fromBytes(Slice(bf.data(), bf.size()));
    return ct && r &&
        confidential::verifyElGamalEncryption(
               *ct, confidential::Scalar::fromUint64(tx[sfMPTAmount]), *r, pk);
}

}  // namespace

// XLS-0096 §7.5: on first use the key is registered and every balance starts
// as the canonical encrypted zero with version 0; the inbox and mirrors are
// then credited with exactly the transaction's ciphertexts.
bool
ValidConfidentialMPToken::validConvert(
    STTx const& tx,
    SLE const* before,
    SLE const& after,
    SLE const& issuance)
{
    using namespace confidential;
    auto const account = tx[sfAccount];
    auto const id = tx[sfMPTokenIssuanceID];
    auto const key = pointField(after, sfHolderEncryptionKey);
    auto const issuerKey = pointField(issuance, sfIssuerEncryptionKey);
    auto const auditorKey = pointField(issuance, sfAuditorEncryptionKey);
    if (!key || !issuerKey)
        return false;

    bool const registering = tx.isFieldPresent(sfHolderEncryptionKey);
    if (registering)
    {
        if ((before && before->isFieldPresent(sfHolderEncryptionKey)) ||
            tx.getFieldVL(sfHolderEncryptionKey) != after.getFieldVL(sfHolderEncryptionKey) ||
            versionOf(&after) != 0 ||
            ciphertextField(after, sfConfidentialBalanceSpending) !=
                encryptedZero(account, id, *key))
            return false;
    }
    else if (
        !before || !sameField(*before, after, sfConfidentialBalanceSpending) ||
        versionOf(before) != versionOf(&after))
    {
        return false;
    }

    auto const credited = [&](SF_VL const& balance, SF_VL const& amount, Point const& pk) {
        auto const start = registering
            ? std::optional<ElGamalCiphertext>{encryptedZero(account, id, pk)}
            : ciphertextField(*before, balance);
        auto const credit = ciphertextField(tx, amount);
        return start && credit && disclosed(tx, amount, pk) &&
            ciphertextField(after, balance) == *start + *credit;
    };
    return credited(sfConfidentialBalanceInbox, sfHolderEncryptedAmount, *key) &&
        credited(sfIssuerEncryptedBalance, sfIssuerEncryptedAmount, *issuerKey) &&
        (!auditorKey || credited(sfAuditorEncryptedBalance, sfAuditorEncryptedAmount, *auditorKey));
}

// XLS-0096 §10.5 and updated spec eq. (8)-(10), (42)-(45): ConvertBack and
// the sender of a Send debit the spending balance and the mirrors by exactly
// the transaction's ciphertexts, advance the version by one and leave the key
// and inbox untouched.
bool
ValidConfidentialMPToken::validDebit(
    STTx const& tx,
    SLE const* before,
    SLE const& after,
    SLE const& issuance,
    SF_VL const& holderAmount)
{
    using namespace confidential;
    auto const key = before ? pointField(*before, sfHolderEncryptionKey) : std::optional<Point>{};
    auto const issuerKey = pointField(issuance, sfIssuerEncryptionKey);
    auto const auditorKey = pointField(issuance, sfAuditorEncryptionKey);
    if (!key || !issuerKey)
        return false;
    auto const debited = [&](SF_VL const& balance, SF_VL const& amount, Point const& pk) {
        auto const start = ciphertextField(*before, balance);
        auto const debit = ciphertextField(tx, amount);
        // A Send's amount is hidden; its sigma proof binds the ciphertexts.
        return start && debit &&
            (!tx.isFieldPresent(sfBlindingFactor) || disclosed(tx, amount, pk)) &&
            ciphertextField(after, balance) == *start - *debit;
    };
    return versionOf(&after) == static_cast<std::uint32_t>(versionOf(before) + 1) &&
        sameField(*before, after, sfHolderEncryptionKey) &&
        sameField(*before, after, sfConfidentialBalanceInbox) &&
        debited(sfConfidentialBalanceSpending, holderAmount, *key) &&
        debited(sfIssuerEncryptedBalance, sfIssuerEncryptedAmount, *issuerKey) &&
        (!auditorKey || debited(sfAuditorEncryptedBalance, sfAuditorEncryptedAmount, *auditorKey));
}

// Updated spec eq. (11)-(13): a Send credits the receiver's inbox and mirrors
// with the transaction's ciphertexts re-randomized by Enc(0; e), and leaves
// its key, spending balance and version untouched.
bool
ValidConfidentialMPToken::validReceive(
    STTx const& tx,
    SLE const* before,
    SLE const& after,
    SLE const& issuance)
{
    using namespace confidential;
    auto const e = confidential_mpt::sendChallenge(tx);
    auto const key = pointField(after, sfHolderEncryptionKey);
    auto const issuerKey = pointField(issuance, sfIssuerEncryptionKey);
    auto const auditorKey = pointField(issuance, sfAuditorEncryptionKey);
    if (!before || !e || !key || !issuerKey)
        return false;
    auto const credited = [&](SF_VL const& balance, SF_VL const& amount, Point const& pk) {
        auto const start = ciphertextField(*before, balance);
        auto const credit = ciphertextField(tx, amount);
        return start && credit &&
            ciphertextField(after, balance) == *start + *credit + elGamalEncrypt(Scalar{}, *e, pk);
    };
    return sameField(*before, after, sfHolderEncryptionKey) &&
        sameField(*before, after, sfConfidentialBalanceSpending) &&
        versionOf(before) == versionOf(&after) &&
        credited(sfConfidentialBalanceInbox, sfDestinationEncryptedAmount, *key) &&
        credited(sfIssuerEncryptedBalance, sfIssuerEncryptedAmount, *issuerKey) &&
        (!auditorKey || credited(sfAuditorEncryptedBalance, sfAuditorEncryptedAmount, *auditorKey));
}

// XLS-0096 §11.4 and updated spec eq. (63)-(66): every balance of the holder
// becomes the canonical encrypted zero under its key, the version advances
// by one and the key is untouched.
bool
ValidConfidentialMPToken::validClawback(
    STTx const& tx,
    SLE const* before,
    SLE const& after,
    SLE const& issuance)
{
    using namespace confidential;
    auto const holder = tx[sfHolder];
    auto const id = tx[sfMPTokenIssuanceID];
    auto const key = pointField(after, sfHolderEncryptionKey);
    auto const issuerKey = pointField(issuance, sfIssuerEncryptionKey);
    auto const auditorKey = pointField(issuance, sfAuditorEncryptionKey);
    if (!before || !key || !issuerKey)
        return false;
    auto const zeroed = [&](SF_VL const& field, Point const& pk) {
        return ciphertextField(after, field) == encryptedZero(holder, id, pk);
    };
    return versionOf(&after) == static_cast<std::uint32_t>(versionOf(before) + 1) &&
        sameField(*before, after, sfHolderEncryptionKey) &&
        zeroed(sfConfidentialBalanceSpending, *key) && zeroed(sfConfidentialBalanceInbox, *key) &&
        zeroed(sfIssuerEncryptedBalance, *issuerKey) &&
        (!auditorKey || zeroed(sfAuditorEncryptedBalance, *auditorKey));
}

// XLS-0096 §9.3: the inbox moves into the spending balance, the inbox resets
// to the canonical encrypted zero, the version advances by one and the key
// and mirrors are untouched.
bool
ValidConfidentialMPToken::validMerge(STTx const& tx, SLE const* before, SLE const& after)
{
    using namespace confidential;
    if (!before)
        return false;
    auto const key = pointField(after, sfHolderEncryptionKey);
    auto const spending = ciphertextField(*before, sfConfidentialBalanceSpending);
    auto const inbox = ciphertextField(*before, sfConfidentialBalanceInbox);
    return key && spending && inbox &&
        versionOf(&after) == static_cast<std::uint32_t>(versionOf(before) + 1) &&
        ciphertextField(after, sfConfidentialBalanceSpending) == *spending + *inbox &&
        ciphertextField(after, sfConfidentialBalanceInbox) ==
        encryptedZero(tx[sfAccount], tx[sfMPTokenIssuanceID], *key) &&
        sameField(*before, after, sfHolderEncryptionKey) &&
        sameField(*before, after, sfIssuerEncryptedBalance) &&
        sameField(*before, after, sfAuditorEncryptedBalance);
}

void
ValidMPTPayment::visitEntry(
    bool,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    auto makeKey = [](SLE const& sle) {
        if (sle.getType() == ltMPTOKEN_ISSUANCE)
            return makeMptID(sle[sfSequence], sle[sfIssuer]);
        return sle[sfMPTokenIssuanceID];
    };

    // An overflowed amount marks its issuance as failed; the other amounts
    // are still recorded so the confidential delta stays accurate.
    auto update = [&](SLE const& sle, Order order) {
        auto const type = sle.getType();
        auto const index = static_cast<std::size_t>(order);
        if (type == ltMPTOKEN_ISSUANCE)
        {
            auto const outstanding = sle[sfOutstandingAmount];
            auto const confidentialOutstanding = sle[sfConfidentialOutstandingAmount];
            auto& data = data_[makeKey(sle)];
            if (outstanding > kMaxMpTokenAmount)
            {
                data.overflow = true;
            }
            else
            {
                data.outstanding[index] = outstanding;
            }
            if (confidentialOutstanding > kMaxMpTokenAmount)
            {
                data.overflow = true;
                data.confidentialOverflow = true;
            }
            else
            {
                data.confidentialOutstanding[index] = confidentialOutstanding;
            }
        }
        else if (type == ltMPTOKEN)
        {
            auto const mptAmt = sle[sfMPTAmount];
            auto const lockedAmt = sle[~sfLockedAmount].value_or(0);
            auto& data = data_[makeKey(sle)];
            if (mptAmt > kMaxMpTokenAmount || lockedAmt > kMaxMpTokenAmount ||
                lockedAmt > (kMaxMpTokenAmount - mptAmt))
            {
                data.overflow = true;
                return;
            }
            auto const res = static_cast<std::int64_t>(mptAmt + lockedAmt);
            // subtract before from after; many large holdings could overflow
            // the running sum.
            auto const signedMax = static_cast<std::int64_t>(kMaxMpTokenAmount);
            if (order == Order::Before)
            {
                if (data.mptAmount < -signedMax + res)
                {
                    data.overflow = true;
                    return;
                }
                data.mptAmount -= res;
            }
            else
            {
                if (data.mptAmount > signedMax - res)
                {
                    data.overflow = true;
                    return;
                }
                data.mptAmount += res;
            }
        }
    };

    if (after && after->getType() == ltMPTOKEN &&
        confidentialFieldsDiffer(before.get(), after.get()))
        data_[makeKey(*after)].confidentialActivity = true;

    if (before)
        update(*before, Order::Before);

    if (after)
    {
        if (after->getType() == ltMPTOKEN_ISSUANCE &&
            (*after)[sfOutstandingAmount] > maxMPTAmount(*after))
        {
            data_[makeKey(*after)].overflow = true;
        }
        update(*after, Order::After);
    }
}

bool
ValidMPTPayment::finalize(
    STTx const& tx,
    TER const result,
    XRPAmount const,
    ReadView const& view,
    beast::Journal const& j)
{
    if (isTesSuccess(result))
    {
        bool const mptV2Enabled = view.rules().enabled(featureMPTokensV2);
        // The confidential supply rules are enforced with ConfidentialTransfer
        // itself rather than waiting for MPTokensV2.
        bool const confidentialEnforced = view.rules().enabled(featureConfidentialTransfer);

        // Check every issuance before deciding: whether a failure is enforced
        // differs per issuance, and data_ has no deterministic order.
        bool failed = false;
        bool enforcedFailure = false;
        auto const signedMax = static_cast<std::int64_t>(kMaxMpTokenAmount);
        for (auto const& [id, data] : data_)
        {
            (void)id;
            static constexpr auto kIBefore = static_cast<std::size_t>(Order::Before);
            static constexpr auto kIAfter = static_cast<std::size_t>(Order::After);
            // Tokens moved into or out of confidential balances leave the
            // public MPTAmounts but stay in OutstandingAmount.
            // COA cannot legitimately change before the amendment.
            auto const confidentialDelta = confidentialEnforced
                ? data.confidentialOutstanding[kIAfter] - data.confidentialOutstanding[kIBefore]
                : std::int64_t{0};
            bool const enforced = confidentialEnforced &&
                (data.confidentialOverflow || confidentialDelta != 0 || data.confidentialActivity);
            if (data.overflow)
            {
                JLOG(j.fatal()) << "Invariant failed: OutstandingAmount overflow";
                failed = true;
                enforcedFailure = enforcedFailure || enforced;
                continue;
            }
            bool const deltaOverflows =
                (confidentialDelta > 0 && data.mptAmount > (signedMax - confidentialDelta)) ||
                (confidentialDelta < 0 && data.mptAmount < (-signedMax - confidentialDelta));
            auto const delta = deltaOverflows ? 0 : data.mptAmount + confidentialDelta;
            bool const addOverflows = deltaOverflows ||
                (delta > 0 && data.outstanding[kIBefore] > (signedMax - delta)) ||
                (delta < 0 && data.outstanding[kIBefore] < (-signedMax - delta));
            if (addOverflows || data.outstanding[kIAfter] != (data.outstanding[kIBefore] + delta))
            {
                JLOG(j.fatal()) << "Invariant failed: invalid OutstandingAmount balance "
                                << data.outstanding[kIBefore] << " " << data.outstanding[kIAfter]
                                << " " << data.mptAmount << " " << confidentialDelta;
                failed = true;
                enforcedFailure = enforcedFailure || enforced;
            }
        }
        if (failed)
            return !mptV2Enabled && !enforcedFailure;
    }

    return true;
}

void
ValidConfidentialMPToken::visitIssuance(bool isDelete, SLE const* before, SLE const& after)
{
    if (isDelete)
    {
        // The committed state is authoritative; the erased copy may have been
        // edited before erasure.
        if ((*(before ? before : &after))[sfConfidentialOutstandingAmount] != 0)
            issuanceDeletedWithCOA_ = true;
        return;
    }

    bool const confidential = after.isFlag(lsfMPTCanHoldConfidentialBalance);
    auto const coa = after[sfConfidentialOutstandingAmount];
    if (coa > after[sfOutstandingAmount])
        coaExceedsOutstanding_ = true;
    if (coa != 0 && !confidential)
        coaWithoutConfidentialFlag_ = true;
    if ((after[sfImmutableFlags] & ~lsifMPTCanHoldConfidentialBalance) != 0u)
        immutableFlagsInvalid_ = true;
    if (after[sfTransferFee] != 0 && confidential)
        transferFeeWithConfidential_ = true;

    bool const hasIssuerKey = after.isFieldPresent(sfIssuerEncryptionKey);
    bool const hasAuditorKey = after.isFieldPresent(sfAuditorEncryptionKey);
    if ((hasIssuerKey || hasAuditorKey) && (!confidential || !hasIssuerKey))
        issuanceKeysInvalid_ = true;
    if (!validKeyField(after, sfIssuerEncryptionKey) ||
        !validKeyField(after, sfAuditorEncryptionKey))
        malformedConfidentialFields_ = true;
    // Convert verifies IssuerEncryptedAmount against the issuer key, so
    // confidential tokens cannot circulate without it.
    if (coa != 0 && !hasIssuerKey)
        coaWithoutIssuerKey_ = true;

    if (!before)
        return;

    bool const wasConfidential = before->isFlag(lsfMPTCanHoldConfidentialBalance);
    if ((wasConfidential && !confidential) ||
        (((*before)[sfImmutableFlags] & lsifMPTCanHoldConfidentialBalance) != 0u &&
         wasConfidential != confidential))
        confidentialFlagChanged_ = true;

    if ((*before)[sfImmutableFlags] != after[sfImmutableFlags])
        immutableFlagsInvalid_ = true;

    if (blobChanged(*before, after, sfIssuerEncryptionKey) ||
        blobChanged(*before, after, sfAuditorEncryptionKey))
        issuanceKeysInvalid_ = true;

    // An auditor key is only registered together with the issuer key, so no
    // holder can have initialized without an auditor mirror it later needs.
    if (!before->isFieldPresent(sfAuditorEncryptionKey) && hasAuditorKey &&
        before->isFieldPresent(sfIssuerEncryptionKey))
        issuanceKeysInvalid_ = true;

    // XLS-0096 §12.4.2: keys cannot be uploaded once tokens are in
    // confidential circulation.
    if ((*before)[sfConfidentialOutstandingAmount] != 0 &&
        ((!before->isFieldPresent(sfIssuerEncryptionKey) && hasIssuerKey) ||
         (!before->isFieldPresent(sfAuditorEncryptionKey) && hasAuditorKey)))
        issuanceKeysInvalid_ = true;
}

void
ValidConfidentialMPToken::visitMPToken(bool isDelete, SLE const* before, SLE const& after)
{
    if (isDelete)
    {
        // XLS-0096 §7.4: an MPToken cannot be deleted once confidential
        // fields are initialized, even if every balance is an encrypted zero,
        // unless its issuance is gone (see MPTokenAuthorize); finalize checks.
        auto const& deleted = before ? *before : after;
        if (hasConfidentialState(deleted))
            confidentialTokensDeleted_.push_back(deleted[sfMPTokenIssuanceID]);
        return;
    }

    bool const hasHolderBalance = after.isFieldPresent(sfConfidentialBalanceSpending) ||
        after.isFieldPresent(sfConfidentialBalanceInbox);
    if (hasHolderBalance != after.isFieldPresent(sfIssuerEncryptedBalance))
        inconsistentEncryptedFields_ = true;

    // Convert initializes the key, both holder balances and the issuer mirror
    // at once (with the version at its default 0); the auditor mirror
    // depends on the issuance.
    if (hasConfidentialState(after) &&
        !(after.isFieldPresent(sfHolderEncryptionKey) &&
          after.isFieldPresent(sfConfidentialBalanceSpending) &&
          after.isFieldPresent(sfConfidentialBalanceInbox) &&
          after.isFieldPresent(sfIssuerEncryptedBalance)))
        incompleteConfidentialFields_ = true;

    if (!validKeyField(after, sfHolderEncryptionKey) ||
        !validCiphertextField(after, sfConfidentialBalanceSpending) ||
        !validCiphertextField(after, sfConfidentialBalanceInbox) ||
        !validCiphertextField(after, sfIssuerEncryptedBalance) ||
        !validCiphertextField(after, sfAuditorEncryptedBalance))
        malformedConfidentialFields_ = true;

    // A default field explicitly holding its default serializes, but the
    // entry then fails to deserialize.
    if (after.isFieldPresent(sfConfidentialBalanceVersion) && versionOf(&after) == 0)
        explicitDefaultVersion_ = true;

    // The version starts at 0 and every change advances it by exactly one,
    // wrapping at 2^32.
    auto const versionAfter = versionOf(&after);
    auto const versionBefore = versionOf(before);
    if (before ? (versionAfter != versionBefore &&
                  versionAfter != static_cast<std::uint32_t>(versionBefore + 1))
               : versionAfter != 0)
        badVersionStep_ = true;

    if (hasConfidentialState(after) &&
        after.key() != keylet::mptoken(after[sfMPTokenIssuanceID], after[sfAccount]).key)
        identityChanged_ = true;

    if (hasEncryptedBalance(after) && confidentialFieldsDiffer(before, &after))
    {
        encryptedTokens_.push_back(
            {.issuanceID = after[sfMPTokenIssuanceID],
             .hasAuditorBalance = after.isFieldPresent(sfAuditorEncryptedBalance)});
    }

    if (!before)
        return;

    if (std::ranges::any_of(kConfidentialMPTokenFields, [&](SField const* f) {
            return before->isFieldPresent(*f) && !after.isFieldPresent(*f);
        }))
        confidentialStateRemoved_ = true;

    if (blobChanged(*before, after, sfHolderEncryptionKey))
        holderKeyChanged_ = true;

    // Ciphertexts are bound to their holder and issuance keys.
    if (hasConfidentialState(*before) &&
        ((*before)[sfMPTokenIssuanceID] != after[sfMPTokenIssuanceID] ||
         (*before)[sfAccount] != after[sfAccount]))
        identityChanged_ = true;

    // Initializing the spending balance is not a modification: XLS-0096 sets
    // it to an encrypted zero together with version 0 on the first Convert.
    if (before->isFieldPresent(sfConfidentialBalanceSpending) &&
        after.isFieldPresent(sfConfidentialBalanceSpending) &&
        before->getFieldVL(sfConfidentialBalanceSpending) !=
            after.getFieldVL(sfConfidentialBalanceSpending) &&
        versionOf(before) == versionOf(&after))
        spendingChangedWithoutVersion_ = true;
}

void
ValidConfidentialMPToken::recordChanges(
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    auto const& sle = after ? *after : *before;
    if (sle.getType() == ltMPTOKEN_ISSUANCE)
    {
        auto const value = [](std::shared_ptr<SLE const> const& s) {
            return s ? (*s)[sfConfidentialOutstandingAmount] : 0;
        };
        if (value(before) != value(after))
            confidentialChanged_ = true;

        auto const outstanding = amountDelta(before.get(), after.get(), sfOutstandingAmount);
        auto const confidential =
            amountDelta(before.get(), after.get(), sfConfidentialOutstandingAmount);
        if (!outstanding || !confidential)
        {
            amountOverflow_ = true;
        }
        else if (*outstanding != 0 || *confidential != 0)
        {
            supplyChanges_[makeMptID(sle[sfSequence], sle[sfIssuer])] = {
                .outstanding = *outstanding, .confidentialOutstanding = *confidential};
        }
        return;
    }

    // Deleting confidential state is checked against its issuance instead.
    bool const confidential = confidentialFieldsDiffer(before.get(), after.get());
    if (confidential && after)
        confidentialChanged_ = true;
    auto const amount = amountDelta(before.get(), after.get(), sfMPTAmount);
    if (!amount)
        amountOverflow_ = true;
    if (confidential || amount.value_or(0) != 0)
    {
        tokenChanges_.push_back(
            {.issuanceID = sle[sfMPTokenIssuanceID],
             .account = sle[sfAccount],
             .amount = amount.value_or(0),
             .before = before,
             .after = after});
    }
}

void
ValidConfidentialMPToken::visitEntry(
    bool isDelete,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    if (!after)
        return;  // LCOV_EXCL_LINE

    auto const type = after->getType();
    if (type != ltMPTOKEN_ISSUANCE && type != ltMPTOKEN)
        return;

    if (type == ltMPTOKEN_ISSUANCE)
    {
        visitIssuance(isDelete, before.get(), *after);
    }
    else
    {
        visitMPToken(isDelete, before.get(), *after);
    }

    // A deleted entry leaves nothing behind; its committed state is `before`.
    if (!isDelete || before)
        recordChanges(before, isDelete ? nullptr : after);
}

bool
ValidConfidentialMPToken::validConfidentialChanges(STTx const& tx, ReadView const& view) const
{
    if (amountOverflow_)
        return false;

    // XLS-0096 §6.5, §7.5, §8.4, §9.3, §10.5 and §11.4.
    SupplyChange expected;
    std::int64_t accountAmount = 0;
    switch (tx.getTxnType())
    {
        case ttCONFIDENTIAL_MPT_CONVERT: {
            auto const amount = tx[sfMPTAmount];
            if (amount > kMaxMpTokenAmount)
                return false;
            expected.confidentialOutstanding = static_cast<std::int64_t>(amount);
            accountAmount = -expected.confidentialOutstanding;
            break;
        }
        case ttCONFIDENTIAL_MPT_CONVERT_BACK: {
            auto const amount = tx[sfMPTAmount];
            if (amount > kMaxMpTokenAmount)
                return false;
            accountAmount = static_cast<std::int64_t>(amount);
            expected.confidentialOutstanding = -accountAmount;
            break;
        }
        case ttCONFIDENTIAL_MPT_CLAWBACK: {
            auto const amount = tx[sfMPTAmount];
            if (amount > kMaxMpTokenAmount)
                return false;
            expected.outstanding = -static_cast<std::int64_t>(amount);
            expected.confidentialOutstanding = expected.outstanding;
            break;
        }
        case ttCONFIDENTIAL_MPT_MERGE_INBOX:
        case ttCONFIDENTIAL_MPT_SEND:
            break;
        // LCOV_EXCL_START
        default:
            UNREACHABLE("xrpl::ValidConfidentialMPToken : unknown confidential transaction");
            return false;
            // LCOV_EXCL_STOP
    }

    auto const id = tx[sfMPTokenIssuanceID];
    // The issuer submits a clawback; the holder's MPToken is the one changed.
    auto const account =
        tx.getTxnType() == ttCONFIDENTIAL_MPT_CLAWBACK ? tx[sfHolder] : tx[sfAccount];

    auto const it = supplyChanges_.find(id);
    bool const touched = it != supplyChanges_.end();
    if (supplyChanges_.size() != (touched ? 1u : 0u) ||
        (touched ? it->second : SupplyChange{}) != expected)
        return false;

    // Each changes exactly its parties' MPTokens: Convert always credits the
    // inbox, and the others always advance the version.
    bool const send = tx.getTxnType() == ttCONFIDENTIAL_MPT_SEND;
    auto const issuance = view.read(keylet::mptIssuance(id));
    if (tokenChanges_.size() != (send ? 2u : 1u) || !issuance)
        return false;
    auto const changeOf = [&](AccountID const& party) -> TokenChange const* {
        auto const matches = [&](TokenChange const& c) { return c.account == party; };
        if (std::ranges::count_if(tokenChanges_, matches) != 1)
            return nullptr;
        auto const& c = *std::ranges::find_if(tokenChanges_, matches);
        return c.issuanceID == id && c.after ? &c : nullptr;
    };
    auto const* change = changeOf(account);
    if (!change || change->amount != accountAmount)
        return false;

    switch (tx.getTxnType())
    {
        case ttCONFIDENTIAL_MPT_CONVERT:
            return validConvert(tx, change->before.get(), *change->after, *issuance);
        case ttCONFIDENTIAL_MPT_CONVERT_BACK:
            return validDebit(
                tx, change->before.get(), *change->after, *issuance, sfHolderEncryptedAmount);
        case ttCONFIDENTIAL_MPT_CLAWBACK:
            return validClawback(tx, change->before.get(), *change->after, *issuance);
        case ttCONFIDENTIAL_MPT_SEND: {
            auto const* receiver = changeOf(tx[sfDestination]);
            return receiver && receiver->amount == 0 &&
                validDebit(
                       tx,
                       change->before.get(),
                       *change->after,
                       *issuance,
                       sfSenderEncryptedAmount) &&
                validReceive(tx, receiver->before.get(), *receiver->after, *issuance);
        }
        default:
            return validMerge(tx, change->before.get(), *change->after);
    }
}

bool
ValidConfidentialMPToken::finalize(
    STTx const& tx,
    TER const result,
    XRPAmount const,
    ReadView const& view,
    beast::Journal const& j) const
{
    if (!view.rules().enabled(featureConfidentialTransfer))
        return true;

    bool invariantPasses = true;
    auto const fail = [&](char const* message) {
        JLOG(j.fatal()) << "Invariant failed: " << message;
        invariantPasses = false;
    };

    if (coaExceedsOutstanding_)
        fail("ConfidentialOutstandingAmount exceeds OutstandingAmount");
    if (coaWithoutConfidentialFlag_)
        fail("ConfidentialOutstandingAmount without lsfMPTCanHoldConfidentialBalance");
    if (confidentialFlagChanged_)
        fail("lsfMPTCanHoldConfidentialBalance changed illegally");
    if (immutableFlagsInvalid_)
        fail("MPTokenIssuance ImmutableFlags invalid or changed");
    if (issuanceKeysInvalid_)
        fail("MPTokenIssuance encryption keys invalid or changed");
    if (transferFeeWithConfidential_)
        fail("MPTokenIssuance has both a TransferFee and confidential balances");
    if (issuanceDeletedWithCOA_)
        fail("MPTokenIssuance deleted with non-zero ConfidentialOutstandingAmount");
    if (inconsistentEncryptedFields_)
        fail("MPToken holder and issuer encrypted balances are inconsistent");
    if (incompleteConfidentialFields_)
        fail("MPToken confidential fields are incomplete");
    if (holderKeyChanged_)
        fail("MPToken HolderEncryptionKey changed");
    if (identityChanged_)
        fail("MPToken with confidential state changed its holder or issuance");
    if (spendingChangedWithoutVersion_)
        fail("MPToken ConfidentialBalanceSpending changed without a version change");
    if (confidentialStateRemoved_ ||
        std::ranges::any_of(confidentialTokensDeleted_, [&](uint192 const& id) {
            return view.exists(keylet::mptIssuance(id));
        }))
        fail("MPToken confidential state removed");
    if (malformedConfidentialFields_)
        fail("confidential key or ciphertext is not a valid encoding");
    if (coaWithoutIssuerKey_)
        fail("ConfidentialOutstandingAmount without an issuer encryption key");
    if (badVersionStep_)
        fail("MPToken ConfidentialBalanceVersion must start at 0 and advance by one");
    if (explicitDefaultVersion_)
        fail("MPToken ConfidentialBalanceVersion is present with its default value 0");

    bool const privileged = hasPrivilege(tx, MayModifyConfidentialMpt);
    if (privileged && isTesSuccess(result))
    {
        if (!validConfidentialChanges(tx, view))
            fail("confidential transaction changed MPT state incorrectly");
    }
    else if (confidentialChanged_)
    {
        fail(
            privileged ? "failed confidential transaction changed confidential MPT state"
                       : "confidential MPT state changed by a non-confidential transaction");
    }

    for (auto const& token : encryptedTokens_)
    {
        // No transaction can act on the confidential state of an MPToken whose
        // issuance was destroyed.
        auto const sleIssuance = view.read(keylet::mptIssuance(token.issuanceID));
        if (!sleIssuance)
        {
            fail("MPToken holds encrypted balances for a missing issuance");
            break;
        }
        if (!sleIssuance->isFlag(lsfMPTCanHoldConfidentialBalance))
        {
            fail("MPToken holds encrypted balances for an issuance without confidential support");
            break;
        }
        if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        {
            fail("MPToken holds encrypted balances without an issuer encryption key");
            break;
        }
        if (token.hasAuditorBalance != sleIssuance->isFieldPresent(sfAuditorEncryptionKey))
        {
            fail("MPToken auditor balance does not match the issuance auditor key");
            break;
        }
    }

    return invariantPasses;
}

void
ValidMPTTransfer::visitEntry(
    bool isDelete,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    // Record the before/after MPTAmount for each (issuanceID, account) pair
    // so finalize() can determine whether a transfer actually occurred.
    auto update = [&](SLE const& sle, bool isBefore) {
        if (sle.getType() == ltMPTOKEN)
        {
            auto const issuanceID = sle[sfMPTokenIssuanceID];
            auto const account = sle[sfAccount];
            auto const amount = sle[sfMPTAmount];
            if (isBefore)
            {
                amount_[issuanceID][account].amtBefore = amount;
            }
            else
            {
                amount_[issuanceID][account].amtAfter = amount;
            }
            if (isDelete && isBefore)
            {
                deletedAuthorized_[sle.key()] = sle.isFlag(lsfMPTAuthorized);
            }
        }
    };

    if (before)
        update(*before, true);

    if (after)
        update(*after, false);
}

bool
ValidMPTTransfer::isAuthorized(
    ReadView const& view,
    MPTID const& mptid,
    AccountID const& holder,
    bool reqAuth) const
{
    auto const key = keylet::mptoken(mptid, holder);
    auto const it = deletedAuthorized_.find(key.key);
    if (it != deletedAuthorized_.end())
        return !reqAuth || it->second;
    return isTesSuccess(requireAuth(view, MPTIssue{mptid}, holder));
}

bool
ValidMPTTransfer::finalize(
    STTx const& tx,
    TER const,
    XRPAmount const,
    ReadView const& view,
    beast::Journal const& j)
{
    if (hasPrivilege(tx, OverrideFreeze))
        return true;

    // DEX transactions (AMM[Create,Deposit], cross-currency payments, offer creates) are
    // subject to the MPTCanTrade flag in addition to the standard transfer rules.
    // A payment is only DEX if it is a cross-currency payment.
    auto const txnType = tx.getTxnType();
    auto const isDEX = [&] {
        if (txnType == ttPAYMENT)
        {
            // A payment is cross-currency (and thus DEX) only if SendMax is present
            // and its asset differs from the destination asset.
            auto const amount = tx[sfAmount];
            return tx[~sfSendMax].value_or(amount).asset() != amount.asset();
        }
        return txnType == ttAMM_CREATE || txnType == ttAMM_DEPOSIT || txnType == ttOFFER_CREATE;
    }();

    // Only enforce once MPTokensV2 is enabled to preserve consensus with non-V2 nodes.
    // Log invariant failure error even if MPTokensV2 is disabled.
    auto const invariantPasses = !view.rules().enabled(featureMPTokensV2);

    for (auto const& [mptID, values] : amount_)
    {
        std::uint16_t senders = 0;
        std::uint16_t receivers = 0;
        bool invalidTransfer = false;
        auto const sleIssuance = view.read(keylet::mptIssuance(mptID));
        if (!sleIssuance)
        {
            continue;
        }

        // These transactions are recovery/settlement paths. They may move an
        // existing MPT position even after the issuer clears CanTransfer, so
        // holders are not trapped in AMM, vault, or loan protocol accounts.
        auto const waivesCanTransfer = txnType == ttAMM_WITHDRAW ||
            (view.rules().enabled(fixCleanup3_2_0) &&
             (txnType == ttVAULT_WITHDRAW || txnType == ttLOAN_BROKER_COVER_WITHDRAW ||
              txnType == ttLOAN_PAY));
        auto const canTransfer = sleIssuance->isFlag(lsfMPTCanTransfer) || waivesCanTransfer;
        auto const canTrade = sleIssuance->isFlag(lsfMPTCanTrade);
        auto const reqAuth = sleIssuance->isFlag(lsfMPTRequireAuth);

        for (auto const& [account, value] : values)
        {
            // Classify each account as a sender or receiver based on whether their MPTAmount
            // decreased or increased. Count new MPToken holders (no amtBefore) as receivers.
            // Skip deleted MPToken holders (amtAfter is nullopt); deletion requires zero balance.
            if (value.amtAfter.has_value() && value.amtBefore.value_or(0) != *value.amtAfter)
            {
                if (!value.amtBefore.has_value() || *value.amtAfter > *value.amtBefore)
                {
                    ++receivers;
                }
                else
                {
                    ++senders;
                }

                // Check once: if any involved account is frozen, the whole
                // issuance transfer is considered frozen. Only need to check for
                // frozen if there is a transfer of funds.
                if (!invalidTransfer &&
                    (isFrozen(view, account, MPTIssue{mptID}) ||
                     !isAuthorized(view, mptID, account, reqAuth)))
                {
                    invalidTransfer = true;
                }
            }
        }
        // A transfer between holders has occurred (senders > 0 && receivers > 0).
        // Fail if the issuance is frozen, does not permit transfers, or — for
        // DEX transactions — does not permit trading.
        if ((invalidTransfer || !canTransfer || (isDEX && !canTrade)) && senders > 0 &&
            receivers > 0)
        {
            JLOG(j.fatal()) << "Invariant failed: invalid MPToken transfer between holders";
            return invariantPasses;
        }
    }

    return true;
}

}  // namespace xrpl
