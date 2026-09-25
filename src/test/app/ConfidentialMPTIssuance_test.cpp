#include <test/jtx.h>
#include <test/jtx/delegate.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/ledger/Sandbox.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace xrpl::test {

class ConfidentialMPTIssuance_test : public beast::unit_test::Suite
{
    // A valid compressed secp256k1 point k·G.
    static std::string
    keyHex(std::uint64_t k)
    {
        auto const bytes = confidential::mulGenerator(confidential::Scalar::fromUint64(k)).bytes();
        return bytes ? strHex(*bytes) : std::string{};
    }

    static constexpr std::uint32_t kCanMutate = tmfMPTCanMutateCanHoldConfidentialBalance;

    static json::Value
    createJV(
        jtx::Account const& issuer,
        std::uint32_t flags,
        std::optional<std::uint16_t> transferFee = std::nullopt,
        std::optional<std::uint32_t> mutableFlags = std::nullopt)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::MPTokenIssuanceCreate;
        jv[jss::Account] = issuer.human();
        jv[jss::Flags] = flags;
        if (transferFee)
            jv[sfTransferFee.jsonName] = *transferFee;
        if (mutableFlags)
            jv[sfMutableFlags.jsonName] = *mutableFlags;
        return jv;
    }

    static json::Value
    setJV(jtx::Account const& account, MPTID const& id, std::uint32_t flags = 0)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::MPTokenIssuanceSet;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(id);
        jv[jss::Flags] = flags;
        return jv;
    }

    // Enables confidential balances after creation (DynamicMPT's MutableFlags).
    static json::Value
    enableJV(jtx::Account const& account, MPTID const& id)
    {
        auto jv = setJV(account, id);
        jv[sfMutableFlags.jsonName] = tmfMPTSetCanHoldConfidentialBalance;
        return jv;
    }

    // Create an issuance and return its ID.
    static MPTID
    create(jtx::Env& env, json::Value const& jv, jtx::Account const& issuer)
    {
        auto const id = makeMptID(env.seq(issuer), issuer);
        env(jv);
        env.close();
        return id;
    }

    static std::shared_ptr<SLE const>
    issuance(jtx::Env& env, MPTID const& id)
    {
        return env.le(keylet::mptIssuance(id));
    }

    // Directly edit the open ledger to reach states that need the
    // confidential transactors (e.g. a non-zero ConfidentialOutstandingAmount).
    static void
    modifyEntry(jtx::Env& env, Keylet const& k, std::function<void(SLE&)> const& f)
    {
        env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            Sandbox sb(&view, TapNone);
            auto sle = sb.peek(k);
            if (!sle)
                return false;
            f(*sle);
            sb.update(sle);
            sb.apply(view);
            return true;
        });
    }

    static void
    setConfidentialOutstanding(
        jtx::Env& env,
        MPTID const& id,
        std::uint64_t amount,
        std::optional<std::uint64_t> outstanding = std::nullopt)
    {
        modifyEntry(env, keylet::mptIssuance(id), [&](SLE& sle) {
            sle[sfConfidentialOutstandingAmount] = amount;
            if (outstanding)
                sle[sfOutstandingAmount] = *outstanding;
        });
    }

    void
    testCreate(FeatureBitset features)
    {
        testcase("MPTokenIssuanceCreate");
        using namespace jtx;

        Account const alice("alice");
        bool const dynamicMPT = features[featureDynamicMPT];

        // The confidential flag and its mutability need the amendment.
        {
            Env env{*this, features - featureConfidentialTransfer};
            env.fund(XRP(1'000), alice);
            env(createJV(alice, tfMPTCanHoldConfidentialBalance), Ter(temDISABLED));
            if (dynamicMPT)
            {
                env(createJV(alice, 0, std::nullopt, kCanMutate), Ter(temDISABLED));
                env(createJV(alice, 0, std::nullopt, kCanMutate | tmfMPTCanMutateCanLock),
                    Ter(temDISABLED));
                env(createJV(alice, 0, std::nullopt, tmfMPTCanMutateCanLock));
            }
            env(createJV(alice, tfMPTCanTransfer));
        }

        // Without DynamicMPT confidential balances can only be enabled at
        // creation.
        {
            Env env{*this, features - featureDynamicMPT};
            env.fund(XRP(1'000), alice);
            env(createJV(alice, 0, std::nullopt, kCanMutate), Ter(temDISABLED));
            auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        Env env{*this, features};
        env.fund(XRP(1'000), alice);
        env.close();

        // Confidential balances are incompatible with a non-zero TransferFee.
        env(createJV(alice, tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance, 1),
            Ter(temBAD_TRANSFER_FEE));
        env(createJV(alice, tfMPTCanHoldConfidentialBalance, 1), Ter(temBAD_TRANSFER_FEE));
        {
            auto const id =
                create(env, createJV(alice, tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance, 0), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfTransferFee));
        }

        // A non-confidential issuance keeps its TransferFee.
        {
            auto const id = create(env, createJV(alice, tfMPTCanTransfer, 100), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && (*sle)[sfTransferFee] == 100);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        // Enabled at creation.
        {
            auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfMutableFlags));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfConfidentialOutstandingAmount));
        }

        // Off, but may be enabled later; unknown mutable flags still fail.
        if (dynamicMPT)
        {
            auto const id = create(env, createJV(alice, 0, std::nullopt, kCanMutate), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(
                sle && (*sle)[sfMutableFlags] == lsmfMPTCanMutateCanHoldConfidentialBalance);

            env(createJV(alice, 0, std::nullopt, kCanMutate | 0x00000001), Ter(temINVALID_FLAG));
        }

        // Default: off, and fixed.
        {
            auto const id = create(env, createJV(alice, 0), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfMutableFlags));
        }
    }

    void
    testSetPreflight(FeatureBitset features)
    {
        testcase("MPTokenIssuanceSet preflight");
        using namespace jtx;

        Account const alice("alice");
        Account const bob("bob");
        auto const issuerKey = keyHex(0x1111);
        auto const auditorKey = keyHex(0x2222);

        bool const dynamicMPT = features[featureDynamicMPT];

        // Every confidential change needs the amendment.
        {
            Env env{*this, features - featureConfidentialTransfer};
            env.fund(XRP(1'000), alice);
            env.close();
            auto const id = create(env, createJV(alice, tfMPTCanLock), alice);

            env(enableJV(alice, id), Ter(temDISABLED));
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(temDISABLED));
            jv = setJV(alice, id);
            jv[sfAuditorEncryptionKey.jsonName] = auditorKey;
            env(jv, Ter(temDISABLED));
            env(setJV(alice, id, tfMPTLock));
        }

        Env env{*this, features};
        env.fund(XRP(1'000), alice, bob);
        env.close();
        auto const id = create(
            env,
            createJV(
                alice,
                tfMPTCanLock,
                std::nullopt,
                dynamicMPT ? std::optional<std::uint32_t>{kCanMutate} : std::nullopt),
            alice);
        MPTTester mpt(env, alice, id, {bob});
        mpt.authorize({.account = bob});

        // Enabling after creation uses MutableFlags, so it needs DynamicMPT.
        if (!dynamicMPT)
            env(enableJV(alice, id), Ter(temDISABLED));

        // Confidential settings apply to the issuance, not a holder.
        {
            auto jv = enableJV(alice, id);
            jv[sfHolder.jsonName] = bob.human();
            env(jv, Ter(dynamicMPT ? TER{temMALFORMED} : TER{temDISABLED}));

            jv = setJV(alice, id);
            jv[sfHolder.jsonName] = bob.human();
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(temMALFORMED));

            // Locking a holder is unaffected.
            jv = setJV(alice, id, tfMPTLock);
            jv[sfHolder.jsonName] = bob.human();
            env(jv);
        }

        // Keys must be valid 33-byte compressed points.
        for (auto const& bad :
             {std::string(64, 'A'),
              issuerKey + "00",
              std::string("02") + std::string(64, '0'),
              std::string("04") + issuerKey.substr(2)})
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = bad;
            env(jv, Ter(temMALFORMED));

            jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            jv[sfAuditorEncryptionKey.jsonName] = bad;
            env(jv, Ter(temMALFORMED));
        }

        // An auditor key needs an issuer key in the same transaction.
        {
            auto jv = setJV(alice, id);
            jv[sfAuditorEncryptionKey.jsonName] = auditorKey;
            env(jv, Ter(temMALFORMED));
        }

        if (dynamicMPT)
        {
            // Enabling confidential balances together with a TransferFee.
            auto jv = enableJV(alice, id);
            jv[sfTransferFee.jsonName] = 1;
            env(jv, Ter(temBAD_TRANSFER_FEE));

            // Mutations and Flags stay mutually exclusive.
            env(enableJV(alice, id), Txflags(tfMPTLock), Ter(temMALFORMED));

            // There is no flag to clear it again, and unknown bits fail.
            jv = enableJV(alice, id);
            jv[sfMutableFlags.jsonName] = tmfMPTSetCanHoldConfidentialBalance << 1;
            env(jv, Ter(temINVALID_FLAG));
        }

        // Enabling and registering keys in one transaction.
        if (dynamicMPT)
        {
            auto jv = enableJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv);
            env.close();
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && strHex(sle->getFieldVL(sfIssuerEncryptionKey)) == issuerKey);
        }
    }

    void
    testSetPreclaim(FeatureBitset features)
    {
        testcase("MPTokenIssuanceSet preclaim");
        using namespace jtx;

        Account const alice("alice");
        Account const bob("bob");
        auto const issuerKey = keyHex(0x3333);
        auto const auditorKey = keyHex(0x4444);

        Env env{*this, features};
        env.fund(XRP(1'000), alice, bob);
        env.close();
        bool const dynamicMPT = features[featureDynamicMPT];
        auto const mutableOpt = [&](std::uint32_t flags) {
            return dynamicMPT ? std::optional<std::uint32_t>{flags} : std::nullopt;
        };

        // Only the issuer may change the settings.
        {
            auto const id =
                create(env, createJV(alice, tfMPTCanHoldConfidentialBalance, std::nullopt, mutableOpt(kCanMutate)), alice);
            if (dynamicMPT)
                env(enableJV(bob, id), Ter(tecNO_PERMISSION));
            auto jv = setJV(bob, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(tecNO_PERMISSION));
        }

        // Without lsmfMPTCanMutateCanHoldConfidentialBalance the setting is
        // fixed at creation, even for a no-op.
        if (dynamicMPT)
        {
            auto const off = create(env, createJV(alice, 0), alice);
            env(enableJV(alice, off), Ter(tecNO_PERMISSION));
            auto const otherMutable =
                create(env, createJV(alice, 0, std::nullopt, tmfMPTCanMutateCanLock), alice);
            env(enableJV(alice, otherMutable), Ter(tecNO_PERMISSION));

            auto const on = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
            env(enableJV(alice, on), Ter(tecNO_PERMISSION));

            // Keys can still be registered once the flag is on.
            auto jv = setJV(alice, on);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv);
            env.close();
            auto const sle = issuance(env, on);
            BEAST_EXPECT(sle && sle->isFieldPresent(sfIssuerEncryptionKey));
        }

        // An existing TransferFee blocks enabling confidential balances.
        if (dynamicMPT)
        {
            auto const id =
                create(env, createJV(alice, tfMPTCanTransfer, 50, kCanMutate), alice);
            env(enableJV(alice, id), Ter(tecNO_PERMISSION));
        }

        // Confidential balances block setting a non-zero TransferFee.
        if (dynamicMPT)
        {
            auto const id = create(
                env,
                createJV(
                    alice,
                    tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance,
                    std::nullopt,
                    tmfMPTCanMutateTransferFee),
                alice);
            auto jv = setJV(alice, id);
            jv[sfTransferFee.jsonName] = 1;
            env(jv, Ter(tecNO_PERMISSION));
            jv[sfTransferFee.jsonName] = 0;
            env(jv);
        }

        // Keys need confidential balances enabled, before or in the same tx.
        {
            auto const off = create(env, createJV(alice, 0, std::nullopt, mutableOpt(kCanMutate)), alice);
            auto jv = setJV(alice, off);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(tecNO_PERMISSION));
        }
        auto const id = dynamicMPT
            ? create(env, createJV(alice, 0, std::nullopt, kCanMutate), alice)
            : create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
        if (dynamicMPT)
        {
            // Enabling is idempotent and does not need keys.
            env(enableJV(alice, id));
            env(enableJV(alice, id));
            env.close();
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(
                sle && (*sle)[sfMutableFlags] == lsmfMPTCanMutateCanHoldConfidentialBalance);
        }
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv);
            env.close();
        }

        // Registered keys are permanent.
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x5555);
            env(jv, Ter(tecNO_PERMISSION));

            // An auditor key needs an issuer key, which already exists.
            jv[sfAuditorEncryptionKey.jsonName] = auditorKey;
            env(jv, Ter(tecNO_PERMISSION));
        }

        // Both keys at once (enabling in the same transaction where
        // DynamicMPT allows it), then neither can be replaced.
        auto const both = dynamicMPT
            ? create(env, createJV(alice, 0, std::nullopt, kCanMutate), alice)
            : create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
        {
            auto jv = dynamicMPT ? enableJV(alice, both) : setJV(alice, both);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            jv[sfAuditorEncryptionKey.jsonName] = auditorKey;
            env(jv);
            env.close();
            auto const sle = issuance(env, both);
            BEAST_EXPECT(sle && strHex(sle->getFieldVL(sfIssuerEncryptionKey)) == issuerKey);
            BEAST_EXPECT(sle && strHex(sle->getFieldVL(sfAuditorEncryptionKey)) == auditorKey);

            env(jv, Ter(tecNO_PERMISSION));
        }

        // Keys cannot be uploaded once confidential tokens circulate.
        {
            auto const circulating =
                create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
            setConfidentialOutstanding(env, circulating, 10, 10);
            auto jv = setJV(alice, circulating);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(tecNO_PERMISSION));
        }
    }

    void
    testSetWithoutCanLock(FeatureBitset features)
    {
        testcase("MPTokenIssuanceSet without CanLock");
        using namespace jtx;

        // Without SingleAssetVault and DynamicMPT, an issuance that cannot be
        // locked accepted no MPTokenIssuanceSet at all; registering keys is
        // still allowed, while enabling after creation needs DynamicMPT.
        Account const alice("alice");
        Env env{*this, features - featureSingleAssetVault - featureDynamicMPT};
        env.fund(XRP(1'000), alice);
        env.close();

        auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
        env(setJV(alice, id), Ter(tecNO_PERMISSION));
        env(setJV(alice, id, tfMPTLock), Ter(tecNO_PERMISSION));
        env(enableJV(alice, id), Ter(temDISABLED));

        auto jv = setJV(alice, id);
        jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x7777);
        env(jv);
        env.close();
        auto const sle = issuance(env, id);
        BEAST_EXPECT(sle && sle->isFieldPresent(sfIssuerEncryptionKey));
        BEAST_EXPECT(sle && !sle->isFlag(lsfMPTLocked));
    }

    void
    testSetDelegation(FeatureBitset features)
    {
        testcase("MPTokenIssuanceSet delegation");
        using namespace jtx;

        Account const alice("alice");
        Account const bob("bob");
        Env env{*this, features};
        env.fund(XRP(1'000), alice, bob);
        env.close();

        // Without DynamicMPT the issuance starts confidential, so only keys
        // remain to be set.
        bool const dynamicMPT = features[featureDynamicMPT];
        auto const id = dynamicMPT
            ? create(env, createJV(alice, tfMPTCanLock, std::nullopt, kCanMutate), alice)
            : create(env, createJV(alice, tfMPTCanLock | tfMPTCanHoldConfidentialBalance), alice);
        auto const change = [&] {
            auto jv = dynamicMPT ? enableJV(alice, id) : setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x6666);
            return jv;
        };

        // Granular lock permissions do not extend to confidential settings.
        env(delegate::set(alice, bob, {"MPTokenIssuanceLock", "MPTokenIssuanceUnlock"}));
        env.close();
        if (dynamicMPT)
            env(enableJV(alice, id), delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x6666);
            env(jv, delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        }
        env(change(), delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        env(setJV(alice, id, tfMPTLock), delegate::As(bob));
        env.close();

        // A delegate with the full transaction permission may enable them.
        env(delegate::set(alice, bob, {"MPTokenIssuanceSet"}));
        env.close();
        env(change(), delegate::As(bob));
        env.close();
        auto const sle = issuance(env, id);
        BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        BEAST_EXPECT(sle && sle->isFieldPresent(sfIssuerEncryptionKey));
    }

    void
    testDestroy(FeatureBitset features)
    {
        testcase("MPTokenIssuanceDestroy");
        using namespace jtx;

        Account const alice("alice");
        Env env{*this, features};
        env.fund(XRP(1'000), alice);
        env.close();

        auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);

        json::Value destroy;
        destroy[jss::TransactionType] = jss::MPTokenIssuanceDestroy;
        destroy[jss::Account] = alice.human();
        destroy[sfMPTokenIssuanceID.jsonName] = to_string(id);

        // The direct ledger edit lives only in the open ledger, so check the
        // result before closing.
        setConfidentialOutstanding(env, id, 5);
        env(destroy, Ter(tecHAS_OBLIGATIONS));
        BEAST_EXPECT(issuance(env, id));

        setConfidentialOutstanding(env, id, 0);
        env(destroy);
        env.close();
        BEAST_EXPECT(!issuance(env, id));
    }

    void
    testExistingBehaviour(FeatureBitset features)
    {
        testcase("Existing MPTokenIssuanceSet behaviour");
        using namespace jtx;

        // Lock/unlock and plain mutations still work on confidential
        // issuances.
        Account const alice("alice");
        Env env{*this, features};
        env.fund(XRP(1'000), alice);
        env.close();

        auto const id = create(
            env,
            createJV(
                alice,
                tfMPTCanLock | tfMPTCanHoldConfidentialBalance,
                std::nullopt,
                features[featureDynamicMPT]
                    ? std::optional<std::uint32_t>{tmfMPTCanMutateMetadata | kCanMutate}
                    : std::nullopt),
            alice);
        env(setJV(alice, id, tfMPTLock));
        env.close();
        BEAST_EXPECT(issuance(env, id)->isFlag(lsfMPTLocked));
        env(setJV(alice, id, tfMPTUnlock));
        if (features[featureDynamicMPT])
        {
            auto jv = setJV(alice, id);
            jv[sfMPTokenMetadata.jsonName] = strHex(std::string("meta"));
            env(jv);

            // Enabling (a no-op here) combines with other mutations, but
            // not with Flags.
            jv[sfMutableFlags.jsonName] = tmfMPTSetCanHoldConfidentialBalance;
            env(jv);
            env(jv, Txflags(tfMPTLock), Ter(temMALFORMED));
        }
        env.close();
        auto const sle = issuance(env, id);
        BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        BEAST_EXPECT(sle && !sle->isFlag(lsfMPTLocked));
    }

    void
    testDeletionBlocker(FeatureBitset features)
    {
        testcase("MPToken deletion blocker");
        using namespace jtx;

        Account const alice("alice");
        Account const bob("bob");
        Env env{*this, features};
        env.fund(XRP(1'000), alice, bob);
        env.close();

        auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
        MPTTester mpt(env, alice, id, {bob});
        mpt.authorize({.account = bob});

        json::Value unauthorize;
        unauthorize[jss::TransactionType] = jss::MPTokenAuthorize;
        unauthorize[jss::Account] = bob.human();
        unauthorize[sfMPTokenIssuanceID.jsonName] = to_string(id);
        unauthorize[jss::Flags] = tfMPTUnauthorize;

        // Initialized confidential fields block deletion even though the
        // public balance is zero; each field alone is enough. The ledger edits
        // only exist in the open ledger, so nothing is closed until the end.
        std::initializer_list<SField const*> const fields{
            &sfHolderEncryptionKey,
            &sfConfidentialBalanceSpending,
            &sfConfidentialBalanceInbox,
            &sfIssuerEncryptedBalance,
            &sfAuditorEncryptedBalance};
        auto const clear = [&](SLE& sle) {
            for (auto const* f : fields)
                sle.makeFieldAbsent(*f);
        };
        for (SField const* field : fields)
        {
            modifyEntry(env, keylet::mptoken(id, bob), [&](SLE& sle) {
                clear(sle);
                sle.setFieldVL(
                    *static_cast<SF_VL const*>(field),
                    Blob(field == &sfHolderEncryptionKey ? 33 : 66, 0x02));
            });
            env(unauthorize, Ter(tecHAS_OBLIGATIONS));
            BEAST_EXPECT(env.le(keylet::mptoken(id, bob)));
        }

        // Without confidential state the holder can delete the MPToken.
        modifyEntry(env, keylet::mptoken(id, bob), clear);
        env(unauthorize);
        BEAST_EXPECT(!env.le(keylet::mptoken(id, bob)));
        env.close();
        BEAST_EXPECT(!env.le(keylet::mptoken(id, bob)));
    }

    void
    testPublicOperations(FeatureBitset features)
    {
        testcase("Public operations on confidential holders");
        using namespace jtx;

        // Public payments, locking and unlocking must keep working for a holder
        // whose MPToken also carries confidential state.
        Account const alice("alice");
        Account const bob("bob");
        Env env{*this, features};
        env.fund(XRP(1'000), alice, bob);
        env.close();

        auto const id = create(
            env,
            createJV(alice, tfMPTCanLock | tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance),
            alice);
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x8888);
            env(jv);
        }
        MPTTester mpt(env, alice, id, {bob});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);
        env.close();

        auto const pk = confidential::mulGenerator(confidential::Scalar::fromUint64(0x9999));
        auto const zero = confidential::elGamalEncrypt(
                              confidential::Scalar{}, confidential::Scalar::fromUint64(7), pk)
                              .toBuffer();
        auto const holderKey = strUnHex(keyHex(0x9999));
        if (!BEAST_EXPECT(zero && holderKey))
            return;
        Blob const ct(zero->data(), zero->data() + zero->size());
        modifyEntry(env, keylet::mptoken(id, bob), [&](SLE& sle) {
            sle.setFieldVL(sfHolderEncryptionKey, *holderKey);
            sle.setFieldVL(sfConfidentialBalanceSpending, ct);
            sle.setFieldVL(sfConfidentialBalanceInbox, ct);
            sle.setFieldVL(sfIssuerEncryptedBalance, ct);
        });

        // The ledger edit only lives in the open ledger; check before closing.
        env(pay(alice, bob, MPT(mpt)(10)));
        env(pay(bob, alice, MPT(mpt)(5)));
        {
            auto jv = setJV(alice, id, tfMPTLock);
            jv[sfHolder.jsonName] = bob.human();
            env(jv);
            jv[jss::Flags] = tfMPTUnlock;
            env(jv);
        }
        auto const token = env.le(keylet::mptoken(id, bob));
        BEAST_EXPECT(token && (*token)[sfMPTAmount] == 105);
        BEAST_EXPECT(token && token->isFieldPresent(sfConfidentialBalanceSpending));
        BEAST_EXPECT(token && !token->isFlag(lsfMPTLocked));
    }

public:
    void
    run() override
    {
        using namespace jtx;
        auto const all = testableAmendments();
        for (auto const& features : {all, all - featureDynamicMPT})
        {
            testCreate(features);
            testSetPreflight(features);
            testSetPreclaim(features);
            testSetWithoutCanLock(features);
            testSetDelegation(features);
            testDestroy(features);
            testExistingBehaviour(features);
            testDeletionBlocker(features);
            testPublicOperations(features);
        }
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTIssuance, app, xrpl);

}  // namespace xrpl::test
