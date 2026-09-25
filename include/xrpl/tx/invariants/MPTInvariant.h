#pragma once

#include <xrpl/basics/UnorderedContainers.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Journal.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace xrpl {

class ValidMPTIssuance
{
    std::uint32_t mptIssuancesCreated_ = 0;
    std::uint32_t mptIssuancesDeleted_ = 0;

    std::uint32_t mptokensCreated_ = 0;
    std::uint32_t mptokensDeleted_ = 0;
    // non-MPT transactions may attempt to create
    // MPToken by an issuer
    bool mptCreatedByIssuer_ = false;

    /// sfReferenceHolding is intended to be set exactly once at vault
    /// creation and immutable thereafter; true when that rule was violated.
    bool referenceHoldingSetOnCreate_ = false;

    /// True when sfReferenceHolding was mutated on an existing MPTokenIssuance.
    bool referenceHoldingMutated_ = false;

    /// MPTokens and RippleStates deleted during apply. finalize() checks each
    /// holder's AccountRoot to detect vault pseudo-account holdings deleted
    /// outside VaultDelete. All these checks are gated on fixCleanup3_2_0.
    std::vector<std::shared_ptr<SLE const>> deletedHoldings_;

public:
    void
    visitEntry(bool, std::shared_ptr<SLE const> const&, std::shared_ptr<SLE const> const&);

    [[nodiscard]] bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&) const;
};

/** Verify:
 *    - OutstandingAmount <= MaximumAmount for any MPT
 *    - OutstandingAmount after = OutstandingAmount before +
 *         sum (MPT after - MPT before) - this is total MPT credit/debit
 *         + (ConfidentialOutstandingAmount after - before)
 */
class ValidMPTPayment
{
    enum class Order { Before = 0, After = 1 };
    struct MPTData
    {
        std::array<std::int64_t, 2> outstanding{};
        std::array<std::int64_t, 2> confidentialOutstanding{};
        // sum (MPT after - MPT before)
        std::int64_t mptAmount{0};
        // true if a confidential field of one of its MPTokens changed
        bool confidentialActivity{false};
        // true if an amount exceeded its limit; the balance check is skipped
        bool overflow{false};
        bool confidentialOverflow{false};
    };

    // mptid:MPTData
    hash_map<uint192, MPTData> data_;

public:
    void
    visitEntry(bool, std::shared_ptr<SLE const> const&, std::shared_ptr<SLE const> const&);

    bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&);
};

/** Verify the XLS-0096 confidential balance rules that hold for every
 *  transaction.
 *
 *  MPTokenIssuance:
 *    - ConfidentialOutstandingAmount <= OutstandingAmount, and it is only
 *      non-zero with lsfMPTCanHoldConfidentialBalance and an issuer key
 *    - lsfMPTCanHoldConfidentialBalance is never cleared, and never changes
 *      while lsifMPTCanHoldConfidentialBalance is set
 *    - ImmutableFlags never changes and holds only known flags
 *    - encryption keys are valid points, need
 *      lsfMPTCanHoldConfidentialBalance, an auditor key needs an issuer key
 *      and is only added together with it,
 *      keys are never added while ConfidentialOutstandingAmount is non-zero,
 *      and registered keys never change
 *    - a non-zero TransferFee never coexists with confidential balances
 *    - it is not deleted while ConfidentialOutstandingAmount is non-zero
 *
 *  MPToken:
 *    - ConfidentialBalanceSpending or ConfidentialBalanceInbox is present
 *      exactly when IssuerEncryptedBalance is (XLS-0096 §7.4)
 *    - HolderEncryptionKey, both holder balances, IssuerEncryptedBalance and
 *      ConfidentialBalanceVersion are initialized together, and the key and
 *      ciphertexts are valid encodings
 *    - encrypted balances only change for an existing issuance with
 *      lsfMPTCanHoldConfidentialBalance and an issuer key, and
 *      AuditorEncryptedBalance exists
 *      exactly when the issuance has an auditor key
 *    - a registered HolderEncryptionKey never changes, and an MPToken with
 *      confidential state keeps the holder and issuance of its ledger key
 *    - ConfidentialBalanceVersion starts at 0 and advances by exactly one;
 *      changing ConfidentialBalanceSpending changes it
 *    - no confidential field is ever removed, including by deleting it
 *
 *  Transactions:
 *    - only successful transactions with MayModifyConfidentialMpt change
 *      ConfidentialOutstandingAmount or a confidential MPToken field
 *    - a successful confidential transaction changes OutstandingAmount,
 *      ConfidentialOutstandingAmount and MPTAmount exactly as its type
 *      prescribes (XLS-0096 §6.5), and changes only its parties' MPTokens,
 *      each field following the type's state transition
 */
class ValidConfidentialMPToken
{
    struct EncryptedToken
    {
        uint192 issuanceID;
        bool hasAuditorBalance;
    };

    struct SupplyChange
    {
        std::int64_t outstanding = 0;
        std::int64_t confidentialOutstanding = 0;

        bool
        operator==(SupplyChange const&) const = default;
    };

    struct TokenChange
    {
        uint192 issuanceID;
        AccountID account;
        std::int64_t amount;
        std::shared_ptr<SLE const> before;
        // nullptr if the MPToken was deleted.
        std::shared_ptr<SLE const> after;
    };

    bool coaExceedsOutstanding_ = false;
    bool coaWithoutConfidentialFlag_ = false;
    bool confidentialFlagChanged_ = false;
    bool immutableFlagsInvalid_ = false;
    bool issuanceKeysInvalid_ = false;
    bool transferFeeWithConfidential_ = false;
    bool issuanceDeletedWithCOA_ = false;
    bool inconsistentEncryptedFields_ = false;
    bool incompleteConfidentialFields_ = false;
    bool holderKeyChanged_ = false;
    bool identityChanged_ = false;
    bool spendingChangedWithoutVersion_ = false;
    bool confidentialStateRemoved_ = false;
    bool malformedConfidentialFields_ = false;
    bool coaWithoutIssuerKey_ = false;
    bool badVersionStep_ = false;
    // MPTokens that hold encrypted balances after the transaction.
    std::vector<EncryptedToken> encryptedTokens_;

    // ConfidentialOutstandingAmount or a confidential MPToken field changed.
    bool confidentialChanged_ = false;
    // An amount exceeded kMaxMpTokenAmount, so the changes below are unknown.
    bool amountOverflow_ = false;
    // Non-zero OutstandingAmount or ConfidentialOutstandingAmount changes.
    hash_map<uint192, SupplyChange> supplyChanges_;
    // MPTokens whose MPTAmount or confidential fields changed.
    std::vector<TokenChange> tokenChanges_;

    void
    visitIssuance(bool isDelete, SLE const* before, SLE const& after);

    void
    visitMPToken(bool isDelete, SLE const* before, SLE const& after);

    void
    recordChanges(
        std::shared_ptr<SLE const> const& before,
        std::shared_ptr<SLE const> const& after);

    [[nodiscard]] bool
    validConfidentialChanges(STTx const& tx, ReadView const& view) const;

    [[nodiscard]] static bool
    validConvert(STTx const& tx, SLE const* before, SLE const& after, SLE const& issuance);

    [[nodiscard]] static bool
    validDebit(
        STTx const& tx,
        SLE const* before,
        SLE const& after,
        SLE const& issuance,
        SF_VL const& holderAmount);

    [[nodiscard]] static bool
    validReceive(STTx const& tx, SLE const* before, SLE const& after, SLE const& issuance);

    [[nodiscard]] static bool
    validMerge(STTx const& tx, SLE const* before, SLE const& after);

public:
    void
    visitEntry(bool, std::shared_ptr<SLE const> const&, std::shared_ptr<SLE const> const&);

    [[nodiscard]] bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&) const;
};

class ValidMPTTransfer
{
    struct Value
    {
        std::optional<std::uint64_t> amtBefore;
        std::optional<std::uint64_t> amtAfter;
    };
    // MPTID: {holder: Value}
    hash_map<uint192, hash_map<AccountID, Value>> amount_;
    // Deleted MPToken
    // MPToken key: true if MPTAuthorized is set
    hash_map<uint256, bool> deletedAuthorized_;

public:
    void
    visitEntry(bool, std::shared_ptr<SLE const> const&, std::shared_ptr<SLE const> const&);

    bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&);

private:
    /**
     * @brief Check whether a holder is authorized to send or receive an MPToken.
     *
     * Deleted MPToken SLEs are no longer present in the view by the time
     * finalize() runs, so their authorization state is captured during
     * visitEntry() and stored in deletedAuthorized_. For deleted MPTokens,
     * returns true if reqAuth is false or lsfMPTAuthorized was set at deletion.
     * For existing MPTokens, returns the result of requireAuth()
     */
    [[nodiscard]] bool
    isAuthorized(
        ReadView const& view,
        MPTID const& mptid,
        AccountID const& holder,
        bool requireAuth) const;
};

}  // namespace xrpl
