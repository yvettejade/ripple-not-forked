#pragma once

#include <xrpl/beast/utility/Journal.h>
#include <xrpl/ledger/ReadView.h>
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
    };

    // true if OutstandingAmount > MaximumAmount in after for any MPT
    bool overflow_{false};
    // mptid:MPTData
    hash_map<uint192, MPTData> data_;

public:
    void
    visitEntry(bool, std::shared_ptr<SLE const> const&, std::shared_ptr<SLE const> const&);

    bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&);
};

/** Verify the XLS-0096 confidential balance rules that hold for every
 *  transaction:
 *    - ConfidentialOutstandingAmount <= OutstandingAmount
 *    - lsfMPTCanHoldConfidentialBalance is never cleared and ImmutableFlags
 *      never changes
 *    - an MPTokenIssuance is not deleted while ConfidentialOutstandingAmount
 *      is non-zero
 *    - an MPToken holding encrypted balances belongs to an issuance with
 *      lsfMPTCanHoldConfidentialBalance
 *    - an MPToken has ConfidentialBalanceSpending or ConfidentialBalanceInbox
 *      exactly when it has IssuerEncryptedBalance
 *    - a registered HolderEncryptionKey never changes
 *    - changing ConfidentialBalanceSpending changes ConfidentialBalanceVersion
 *    - confidential state is never removed from an MPToken, including by
 *      deleting it
 */
class ValidConfidentialMPToken
{
    bool coaExceedsOutstanding_ = false;
    bool confidentialFlagCleared_ = false;
    bool immutableFlagsChanged_ = false;
    bool issuanceDeletedWithCOA_ = false;
    bool inconsistentEncryptedFields_ = false;
    bool holderKeyChanged_ = false;
    bool spendingChangedWithoutVersion_ = false;
    bool confidentialStateRemoved_ = false;
    // Issuances of MPTokens that hold encrypted balances after the transaction.
    std::vector<uint192> encryptedIssuances_;

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
