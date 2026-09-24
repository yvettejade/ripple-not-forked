#include <test/jtx.h>
#include <test/jtx/delegate.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Blob.h>
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

    static json::Value
    createJV(
        jtx::Account const& issuer,
        std::uint32_t flags,
        std::optional<std::uint32_t> immutableFlags = std::nullopt,
        std::optional<std::uint16_t> transferFee = std::nullopt,
        std::optional<std::uint32_t> mutableFlags = std::nullopt)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::MPTokenIssuanceCreate;
        jv[jss::Account] = issuer.human();
        jv[jss::Flags] = flags;
        if (immutableFlags)
            jv[sfImmutableFlags.jsonName] = *immutableFlags;
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

        // The confidential flag and ImmutableFlags need the amendment.
        {
            Env env{*this, features - featureConfidentialTransfer};
            env.fund(XRP(1'000), alice);
            env(createJV(alice, tfMPTCanHoldConfidentialBalance), Ter(temDISABLED));
            env(createJV(alice, 0, tifMPTCanHoldConfidentialBalance), Ter(temDISABLED));
            env(createJV(alice, tfMPTCanTransfer));
        }

        // XLS-0096 requires DynamicMPT for ImmutableFlags.
        {
            Env env{*this, features - featureDynamicMPT};
            env.fund(XRP(1'000), alice);
            env(createJV(alice, 0, tifMPTCanHoldConfidentialBalance), Ter(temDISABLED));
            auto const id = create(env, createJV(alice, tfMPTCanHoldConfidentialBalance), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        Env env{*this, features};
        env.fund(XRP(1'000), alice);
        env.close();
        bool const dynamicMPT = features[featureDynamicMPT];

        // ImmutableFlags must be non-zero and only contain known flags.
        if (dynamicMPT)
        {
            env(createJV(alice, 0, 0), Ter(temINVALID_FLAG));
            env(createJV(alice, 0, 0x00000001), Ter(temINVALID_FLAG));
            env(createJV(alice, 0, tifMPTCanHoldConfidentialBalance | 0x00000100),
                Ter(temINVALID_FLAG));
        }

        // Confidential balances are incompatible with a non-zero TransferFee.
        env(createJV(alice, tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance, std::nullopt, 1),
            Ter(temBAD_TRANSFER_FEE));
        env(createJV(alice, tfMPTCanHoldConfidentialBalance, std::nullopt, 1),
            Ter(temBAD_TRANSFER_FEE));
        {
            auto const id = create(
                env,
                createJV(
                    alice, tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance, std::nullopt, 0),
                alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfTransferFee));
        }

        // A non-confidential issuance keeps its TransferFee.
        {
            auto const id =
                create(env, createJV(alice, tfMPTCanTransfer, std::nullopt, 100), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && (*sle)[sfTransferFee] == 100);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        // Enabled and locked on.
        if (dynamicMPT)
        {
            auto const id = create(
                env,
                createJV(alice, tfMPTCanHoldConfidentialBalance, tifMPTCanHoldConfidentialBalance),
                alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && (*sle)[sfImmutableFlags] == lsifMPTCanHoldConfidentialBalance);
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfConfidentialOutstandingAmount));
        }

        // Locked off.
        if (dynamicMPT)
        {
            auto const id =
                create(env, createJV(alice, 0, tifMPTCanHoldConfidentialBalance), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && (*sle)[sfImmutableFlags] == lsifMPTCanHoldConfidentialBalance);
        }

        // Default: neither flag.
        {
            auto const id = create(env, createJV(alice, 0), alice);
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && !sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfImmutableFlags));
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

        // Every confidential change needs the amendment.
        {
            Env env{*this, features - featureConfidentialTransfer};
            env.fund(XRP(1'000), alice);
            env.close();
            auto const id = create(env, createJV(alice, tfMPTCanLock), alice);

            env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance), Ter(temDISABLED));
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
        auto const id = create(env, createJV(alice, tfMPTCanLock), alice);
        MPTTester mpt(env, alice, id, {bob});
        mpt.authorize({.account = bob});

        // Confidential settings apply to the issuance, not a holder.
        {
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfHolder.jsonName] = bob.human();
            env(jv, Ter(temMALFORMED));

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
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfIssuerEncryptionKey.jsonName] = bad;
            env(jv, Ter(temMALFORMED));

            jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            jv[sfAuditorEncryptionKey.jsonName] = bad;
            env(jv, Ter(temMALFORMED));
        }

        // An auditor key needs an issuer key in the same transaction.
        {
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfAuditorEncryptionKey.jsonName] = auditorKey;
            env(jv, Ter(temMALFORMED));
        }

        // Enabling confidential balances together with a TransferFee.
        if (features[featureDynamicMPT])
        {
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfTransferFee.jsonName] = 1;
            env(jv, Ter(temBAD_TRANSFER_FEE));

            // Mutating fields and setting flags stay mutually exclusive.
            jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfTransferFee.jsonName] = 0;
            env(jv, Ter(temMALFORMED));
        }

        // Keys alone count as a change.
        {
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
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

        // Only the issuer may change the settings.
        {
            auto const id = create(env, createJV(alice, 0), alice);
            env(setJV(bob, id, tfMPTSetCanHoldConfidentialBalance), Ter(tecNO_PERMISSION));
            auto jv = setJV(bob, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(tecNO_PERMISSION));
        }

        // lsifMPTCanHoldConfidentialBalance freezes the setting.
        if (features[featureDynamicMPT])
        {
            auto const locked =
                create(env, createJV(alice, 0, tifMPTCanHoldConfidentialBalance), alice);
            env(setJV(alice, locked, tfMPTSetCanHoldConfidentialBalance), Ter(tecNO_PERMISSION));

            auto const lockedOn = create(
                env,
                createJV(alice, tfMPTCanHoldConfidentialBalance, tifMPTCanHoldConfidentialBalance),
                alice);
            env(setJV(alice, lockedOn, tfMPTSetCanHoldConfidentialBalance), Ter(tecNO_PERMISSION));

            // Keys can still be registered once the flag is on.
            auto jv = setJV(alice, lockedOn);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv);
            env.close();
            auto const sle = issuance(env, lockedOn);
            BEAST_EXPECT(sle && sle->isFieldPresent(sfIssuerEncryptionKey));
        }

        // An existing TransferFee blocks enabling confidential balances.
        {
            auto const id = create(env, createJV(alice, tfMPTCanTransfer, std::nullopt, 50), alice);
            env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance), Ter(tecNO_PERMISSION));
        }

        // Confidential balances block setting a non-zero TransferFee.
        if (features[featureDynamicMPT])
        {
            auto const id = create(
                env,
                createJV(
                    alice,
                    tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance,
                    std::nullopt,
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
        auto const id = create(env, createJV(alice, 0), alice);
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = issuerKey;
            env(jv, Ter(tecNO_PERMISSION));
        }
        {
            // Enabling is idempotent and does not need keys.
            env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance));
            env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance));
            env.close();
            auto const sle = issuance(env, id);
            BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle && !sle->isFieldPresent(sfIssuerEncryptionKey));
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

        // Both keys at once, then neither can be replaced.
        auto const both = create(env, createJV(alice, 0), alice);
        {
            auto jv = setJV(alice, both, tfMPTSetCanHoldConfidentialBalance);
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
        // locked accepted no MPTokenIssuanceSet at all; confidential changes
        // are still allowed.
        Account const alice("alice");
        Env env{*this, features - featureSingleAssetVault - featureDynamicMPT};
        env.fund(XRP(1'000), alice);
        env.close();

        auto const id = create(env, createJV(alice, 0), alice);
        env(setJV(alice, id), Ter(tecNO_PERMISSION));
        env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance | tfMPTLock),
            Ter(tecNO_PERMISSION));
        env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance));
        env.close();
        auto sle = issuance(env, id);
        BEAST_EXPECT(sle && sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        BEAST_EXPECT(sle && !sle->isFlag(lsfMPTLocked));

        // Keys alone, on an issuance that already allows confidential balances.
        auto jv = setJV(alice, id);
        jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x7777);
        env(jv);
        env.close();
        sle = issuance(env, id);
        BEAST_EXPECT(sle && sle->isFieldPresent(sfIssuerEncryptionKey));
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

        auto const id = create(env, createJV(alice, tfMPTCanLock), alice);

        // Granular lock permissions do not extend to confidential settings.
        env(delegate::set(alice, bob, {"MPTokenIssuanceLock", "MPTokenIssuanceUnlock"}));
        env.close();
        env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance),
            delegate::As(bob),
            Ter(terNO_DELEGATE_PERMISSION));
        env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance | tfMPTLock),
            delegate::As(bob),
            Ter(terNO_DELEGATE_PERMISSION));
        {
            auto jv = setJV(alice, id);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x6666);
            env(jv, delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        }
        env(setJV(alice, id, tfMPTLock), delegate::As(bob));
        env.close();

        // A delegate with the full transaction permission may enable them.
        env(delegate::set(alice, bob, {"MPTokenIssuanceSet"}));
        env.close();
        {
            auto jv = setJV(alice, id, tfMPTSetCanHoldConfidentialBalance);
            jv[sfIssuerEncryptionKey.jsonName] = keyHex(0x6666);
            env(jv, delegate::As(bob));
            env.close();
        }
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
                std::nullopt,
                features[featureDynamicMPT] ? std::optional<std::uint32_t>{tmfMPTCanMutateMetadata}
                                            : std::nullopt),
            alice);
        env(setJV(alice, id, tfMPTLock));
        env(setJV(alice, id, tfMPTUnlock));
        // Enabling (a no-op here) combines with locking.
        env(setJV(alice, id, tfMPTSetCanHoldConfidentialBalance | tfMPTLock));
        env.close();
        BEAST_EXPECT(issuance(env, id)->isFlag(lsfMPTLocked));
        env(setJV(alice, id, tfMPTUnlock));
        if (features[featureDynamicMPT])
        {
            auto jv = setJV(alice, id);
            jv[sfMPTokenMetadata.jsonName] = strHex(std::string("meta"));
            env(jv);

            jv[jss::Flags] = tfMPTSetCanHoldConfidentialBalance;
            env(jv, Ter(temMALFORMED));
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
        }
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTIssuance, app, xrpl);

}  // namespace xrpl::test
