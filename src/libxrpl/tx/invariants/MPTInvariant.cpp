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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

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
constexpr std::array<SField const*, 6> kConfidentialMPTokenFields{
    &sfHolderEncryptionKey,
    &sfConfidentialBalanceSpending,
    &sfConfidentialBalanceInbox,
    &sfIssuerEncryptedBalance,
    &sfAuditorEncryptedBalance,
    &sfConfidentialBalanceVersion};

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
    return std::ranges::any_of(
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
    return std::ranges::any_of(kConfidentialMPTokenFields, [&](SField const* f) {
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

}  // namespace

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
        // fields are initialized, even if every balance is an encrypted zero.
        if (hasConfidentialState(*(before ? before : &after)))
            confidentialStateRemoved_ = true;
        return;
    }

    bool const hasHolderBalance = after.isFieldPresent(sfConfidentialBalanceSpending) ||
        after.isFieldPresent(sfConfidentialBalanceInbox);
    if (hasHolderBalance != after.isFieldPresent(sfIssuerEncryptedBalance))
        inconsistentEncryptedFields_ = true;

    // Convert initializes the key, both holder balances, the issuer mirror
    // and the version at once; the auditor mirror depends on the issuance.
    if (hasConfidentialState(after) &&
        !(after.isFieldPresent(sfHolderEncryptionKey) &&
          after.isFieldPresent(sfConfidentialBalanceSpending) &&
          after.isFieldPresent(sfConfidentialBalanceInbox) &&
          after.isFieldPresent(sfIssuerEncryptedBalance) &&
          after.isFieldPresent(sfConfidentialBalanceVersion)))
        incompleteConfidentialFields_ = true;

    if (!validKeyField(after, sfHolderEncryptionKey) ||
        !validCiphertextField(after, sfConfidentialBalanceSpending) ||
        !validCiphertextField(after, sfConfidentialBalanceInbox) ||
        !validCiphertextField(after, sfIssuerEncryptedBalance) ||
        !validCiphertextField(after, sfAuditorEncryptedBalance))
        malformedConfidentialFields_ = true;

    // The version starts at 0 and every change advances it by exactly one,
    // wrapping at 2^32.
    auto const versionAfter = after[~sfConfidentialBalanceVersion];
    auto const versionBefore =
        before ? (*before)[~sfConfidentialBalanceVersion] : std::optional<std::uint32_t>{};
    if (versionAfter &&
        (versionBefore ? (*versionAfter != *versionBefore &&
                          *versionAfter != static_cast<std::uint32_t>(*versionBefore + 1))
                       : *versionAfter != 0))
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
        (*before)[~sfConfidentialBalanceVersion] == after[~sfConfidentialBalanceVersion])
        spendingChangedWithoutVersion_ = true;
}

void
ValidConfidentialMPToken::visitEntry(
    bool isDelete,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    if (!after)
        return;  // LCOV_EXCL_LINE

    if (after->getType() == ltMPTOKEN_ISSUANCE)
    {
        visitIssuance(isDelete, before.get(), *after);
    }
    else if (after->getType() == ltMPTOKEN)
    {
        visitMPToken(isDelete, before.get(), *after);
    }
}

bool
ValidConfidentialMPToken::finalize(
    STTx const&,
    TER const,
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
    if (confidentialStateRemoved_)
        fail("MPToken confidential state removed");
    if (malformedConfidentialFields_)
        fail("confidential key or ciphertext is not a valid encoding");
    if (coaWithoutIssuerKey_)
        fail("ConfidentialOutstandingAmount without an issuer encryption key");
    if (badVersionStep_)
        fail("MPToken ConfidentialBalanceVersion must start at 0 and advance by one");

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
