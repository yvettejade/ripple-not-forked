#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/delegate.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>

#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <string>

namespace xrpl {

class ConfidentialMPTIssuance_test : public beast::unit_test::Suite
{
    static std::string
    secp256k1KeyHex(char const* seedPhrase)
    {
        auto const keys =
            generateKeyPair(KeyType::Secp256k1, generateSeed(seedPhrase));
        return strHex(keys.first.slice());
    }

    static std::string
    ed25519KeyHex()
    {
        auto const keys = generateKeyPair(KeyType::Ed25519, generateSeed("ed-key"));
        return strHex(keys.first.slice());
    }

    void
    testDisabled(FeatureBitset features)
    {
        testcase("Disabled");
        using namespace test::jtx;

        Env env{*this, features - featureConfidentialTransfer};
        Account const alice("alice");
        MPTTester mpt(env, alice);

        mpt.create(
            {.flags = tfMPTCanHoldConfidentialBalance, .err = temDISABLED});

        mpt.create({.ownerCount = 1});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance, .err = temDISABLED});
        mpt.set(
            {.issuerEncryptionKey = secp256k1KeyHex("iss"), .err = temDISABLED});
    }

    void
    testCreate(FeatureBitset features)
    {
        testcase("Create");
        using namespace test::jtx;

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});

            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(!sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(!sle->isFieldPresent(sfConfidentialOutstandingAmount));
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create(
                {.transferFee = 10,
                 .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer,
                 .err = temBAD_TRANSFER_FEE});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create(
                {.ownerCount = 1,
                 .flags = tfMPTCanHoldConfidentialBalance,
                 .immutableFlags = tifMPTCanHoldConfidentialBalance});

            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(
                (sle->getFieldU32(sfImmutableFlags) &
                 lsifMPTCanHoldConfidentialBalance) != 0u);
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create({.immutableFlags = 0, .err = temINVALID_FLAG});
            mpt.create({.immutableFlags = 0x00000001, .err = temINVALID_FLAG});
        }
    }

    void
    testSet(FeatureBitset features)
    {
        testcase("Set");
        using namespace test::jtx;

        auto const issuerKey = secp256k1KeyHex("issuer-key");
        auto const auditorKey = secp256k1KeyHex("auditor-key");

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create({.ownerCount = 1});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = issuerKey,
                 .auditorEncryptionKey = auditorKey});

            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(strHex((*sle)[sfIssuerEncryptionKey]) == issuerKey);
            BEAST_EXPECT(strHex((*sle)[sfAuditorEncryptionKey]) == auditorKey);
            BEAST_EXPECT(!sle->isFieldPresent(sfConfidentialOutstandingAmount));
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            Account const bob("bob");
            MPTTester mpt(env, alice, {.holders = {bob}});
            mpt.create({.ownerCount = 1});
            mpt.authorize({.account = bob});
            mpt.set(
                {.holder = bob,
                 .flags = tfMPTSetCanHoldConfidentialBalance,
                 .err = temMALFORMED});
            mpt.set(
                {.holder = bob, .issuerEncryptionKey = issuerKey, .err = temMALFORMED});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});
            mpt.set({.auditorEncryptionKey = auditorKey, .err = temMALFORMED});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create({.ownerCount = 1});
            mpt.set({.issuerEncryptionKey = issuerKey, .err = tecNO_PERMISSION});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});
            mpt.set({.issuerEncryptionKey = ed25519KeyHex(), .err = temMALFORMED});
            mpt.set({.issuerEncryptionKey = "aa", .err = temMALFORMED});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create(
                {.ownerCount = 1,
                 .immutableFlags = tifMPTCanHoldConfidentialBalance});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .err = tecNO_PERMISSION});
        }

        {
            Env env{*this, features};
            Account const alice("alice");
            MPTTester mpt(env, alice);
            mpt.create(
                {.transferFee = 25,
                 .ownerCount = 1,
                 .flags = tfMPTCanTransfer});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .err = tecNO_PERMISSION});
        }
    }

    void
    testSetTransferFee(FeatureBitset features)
    {
        testcase("Set transfer fee vs confidential");
        using namespace test::jtx;

        Env env{*this, features | featureDynamicMPT};
        Account const alice("alice");
        MPTTester mpt(env, alice);
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer,
             .mutableFlags = tmfMPTCanMutateTransferFee});
        mpt.set({.transferFee = 10, .err = tecNO_PERMISSION});

        MPTTester mpt2(env, alice, {.fund = false});
        mpt2.create(
            {.ownerCount = 2,
             .flags = tfMPTCanTransfer,
             .mutableFlags = tmfMPTCanMutateTransferFee});
        mpt2.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .transferFee = 10,
             .err = temBAD_TRANSFER_FEE});
    }

    void
    testDuplicateKeys(FeatureBitset features)
    {
        testcase("Duplicate keys");
        using namespace test::jtx;

        auto const issuerKey = secp256k1KeyHex("issuer-key-dup");
        Env env{*this, features};
        Account const alice("alice");
        MPTTester mpt(env, alice);
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});
        mpt.set({.issuerEncryptionKey = issuerKey});
        mpt.set(
            {.issuerEncryptionKey = secp256k1KeyHex("other"),
             .err = tecNO_PERMISSION});
        // Auditor cannot be added later: the tx must include IssuerEncryptionKey,
        // but replacing that key is also forbidden.
        mpt.set({.auditorEncryptionKey = secp256k1KeyHex("aud"), .err = temMALFORMED});
        mpt.set(
            {.issuerEncryptionKey = issuerKey,
             .auditorEncryptionKey = secp256k1KeyHex("aud"),
             .err = tecNO_PERMISSION});
    }

    void
    testDelegateConfidential(FeatureBitset features)
    {
        testcase("Delegate cannot enable confidential or install keys");
        using namespace test::jtx;

        auto const issuerKey = secp256k1KeyHex("delegate-issuer-key");
        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        env.fund(XRP(100000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanLock});

        // Lock-only granular permission must not authorize confidential Set.
        env(delegate::set(alice, bob, {"MPTokenIssuanceLock"}));
        env.close();
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .delegate = bob,
             .err = terNO_DELEGATE_PERMISSION});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = issuerKey,
             .delegate = bob,
             .err = terNO_DELEGATE_PERMISSION});
        mpt.set(
            {.issuerEncryptionKey = issuerKey,
             .delegate = bob,
             .err = terNO_DELEGATE_PERMISSION});

        // Full transaction permission still allows confidential Set.
        env(delegate::set(alice, bob, {"MPTokenIssuanceSet"}));
        env.close();
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = issuerKey,
             .delegate = bob});
        auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        BEAST_EXPECT(strHex((*sle)[sfIssuerEncryptionKey]) == issuerKey);
    }

    void
    testWithFeats(FeatureBitset features)
    {
        testDisabled(features);
        testCreate(features);
        testSet(features);
        testSetTransferFee(features);
        testDuplicateKeys(features);
        testDelegateConfidential(features);
    }

public:
    void
    run() override
    {
        using namespace test::jtx;
        testWithFeats(testableAmendments() | featureConfidentialTransfer);
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTIssuance, app, xrpl);

}  // namespace xrpl
