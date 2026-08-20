#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/delegate.h>
#include <test/jtx/fee.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/protocol/Confidential.h>
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

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace xrpl {

class ConfidentialMPTConvert_test : public beast::unit_test::Suite
{
    static std::pair<PublicKey, SecretKey>
    secpKeys(char const* phrase)
    {
        return generateKeyPair(KeyType::Secp256k1, generateSeed(phrase));
    }

    static uint256
    scalarFromSecret(SecretKey const& sk)
    {
        uint256 r;
        std::memcpy(r.data(), sk.data(), 32);
        return r;
    }

    static Slice
    skSlice(SecretKey const& sk)
    {
        return Slice(sk.data(), sk.size());
    }

    static json::Value
    mergeJV(test::jtx::Account const& account, MPTID const& mptId)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        return jv;
    }

    json::Value
    convertJV(
        test::jtx::Account const& account,
        MPTID const& mptId,
        std::uint64_t amount,
        PublicKey const& holderPk,
        PublicKey const& issuerPk,
        uint256 const& r,
        std::optional<PublicKey> const& auditorPk,
        bool registerKey,
        SecretKey const* holderSk)
    {
        auto const holderCt = elgamalEncrypt(holderPk.slice(), amount, r);
        auto const issuerCt = elgamalEncrypt(issuerPk.slice(), amount, r);
        if (!BEAST_EXPECT(holderCt && issuerCt))
            return json::Value();

        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTConvert;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = strHex(*holderCt);
        jv[sfIssuerEncryptedAmount] = strHex(*issuerCt);
        jv[sfBlindingFactor] = to_string(r);
        if (auditorPk)
        {
            auto const auditorCt = elgamalEncrypt(auditorPk->slice(), amount, r);
            if (!BEAST_EXPECT(auditorCt))
                return json::Value();
            jv[sfAuditorEncryptedAmount] = strHex(*auditorCt);
        }
        if (registerKey)
        {
            if (!BEAST_EXPECT(holderSk))
                return json::Value();
            jv[sfHolderEncryptionKey] = strHex(holderPk.slice());
            auto const transcript = convertSchnorrTranscript(account.id(), mptId);
            auto const proof = schnorrProve(holderPk.slice(), skSlice(*holderSk), transcript);
            if (!BEAST_EXPECT(proof))
                return json::Value();
            jv[sfZKProof] = strHex(*proof);
        }
        return jv;
    }

    void
    testDisabled(FeatureBitset features)
    {
        testcase("Disabled");
        using namespace test::jtx;

        Env env{*this, features - featureConfidentialTransfer};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const [holderPk, holderSk] = secpKeys("h");
        auto const issuerPk = secpKeys("i").first;
        auto const r = scalarFromSecret(secpKeys("r").second);
        env(convertJV(
                bob,
                mpt.issuanceID(),
                10,
                holderPk,
                issuerPk,
                r,
                std::nullopt,
                true,
                &holderSk),
            Ter(temDISABLED));
        env(mergeJV(bob, mpt.issuanceID()), Ter(temDISABLED));
    }

    void
    testConvertAndMerge(FeatureBitset features)
    {
        testcase("Convert and merge");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("issuer-enc").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const [holderPk, holderSk] = secpKeys("holder-enc");
        auto const r = scalarFromSecret(secpKeys("blind-1").second);
        env(convertJV(
            bob, mpt.issuanceID(), 100, holderPk, issuerPk, r, std::nullopt, true, &holderSk));

        auto const sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob));
        auto const sleIssuance = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleMpt && sleIssuance);
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 900);
        BEAST_EXPECT((*sleIssuance)[sfConfidentialOutstandingAmount] == 100);
        BEAST_EXPECT(strHex((*sleMpt)[sfHolderEncryptionKey]) == strHex(holderPk.slice()));
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == 0);

        auto const expectedInbox = elgamalEncrypt(holderPk.slice(), 100, r);
        auto const expectedIssuer = elgamalEncrypt(issuerPk.slice(), 100, r);
        auto const expectedZero =
            encZero(bob.id(), alice.id(), mpt.issuanceID(), holderPk.slice());
        BEAST_EXPECT(expectedInbox && expectedIssuer && expectedZero);
        BEAST_EXPECT(strHex((*sleMpt)[sfConfidentialBalanceInbox]) == strHex(*expectedInbox));
        BEAST_EXPECT(strHex((*sleMpt)[sfIssuerEncryptedBalance]) == strHex(*expectedIssuer));
        BEAST_EXPECT(
            strHex((*sleMpt)[sfConfidentialBalanceSpending]) == strHex(*expectedZero));

        env(mergeJV(bob, mpt.issuanceID()));
        auto const sleMerged = env.le(keylet::mptoken(mpt.issuanceID(), bob));
        BEAST_EXPECT(
            (*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfConfidentialOutstandingAmount] ==
            100);
        BEAST_EXPECT((*sleMerged)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(strHex((*sleMerged)[sfConfidentialBalanceInbox]) == strHex(*expectedZero));
        auto const expectedSpending = elgamalAdd(*expectedZero, *expectedInbox);
        BEAST_EXPECT(expectedSpending);
        BEAST_EXPECT(
            strHex((*sleMerged)[sfConfidentialBalanceSpending]) == strHex(*expectedSpending));

        // Empty inbox: merge is still valid and bumps the version.
        env(mergeJV(bob, mpt.issuanceID()));
        auto const sleAgain = env.le(keylet::mptoken(mpt.issuanceID(), bob));
        BEAST_EXPECT((*sleAgain)[sfConfidentialBalanceVersion] == 2);
        BEAST_EXPECT(strHex((*sleAgain)[sfConfidentialBalanceInbox]) == strHex(*expectedZero));
    }

    void
    testZeroAmountOptIn(FeatureBitset features)
    {
        testcase("Zero-amount opt-in");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("issuer-zero").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 10);

        auto const [holderPk, holderSk] = secpKeys("holder-zero");
        auto const r = scalarFromSecret(secpKeys("blind-zero").second);
        env(convertJV(
            bob, mpt.issuanceID(), 0, holderPk, issuerPk, r, std::nullopt, true, &holderSk));

        auto const sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob));
        auto const sleIssuance = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 10);
        BEAST_EXPECT((*sleIssuance)[sfConfidentialOutstandingAmount] == 0);
        BEAST_EXPECT(sleIssuance->isFieldPresent(sfConfidentialOutstandingAmount));
        BEAST_EXPECT(sleMpt->isFieldPresent(sfConfidentialBalanceSpending));

        mpt.authorize({.account = bob, .flags = tfMPTUnauthorize, .err = tecHAS_OBLIGATIONS});
    }

    void
    testConvertErrors(FeatureBitset features)
    {
        testcase("Convert errors");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("issuer-err").first;
        auto const auditorPk = secpKeys("auditor-err").first;
        mpt.set(
            {.issuerEncryptionKey = strHex(issuerPk.slice()),
             .auditorEncryptionKey = strHex(auditorPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const [holderPk, holderSk] = secpKeys("holder-err");
        auto const r = scalarFromSecret(secpKeys("blind-err").second);

        env(convertJV(
                alice,
                mpt.issuanceID(),
                1,
                holderPk,
                issuerPk,
                r,
                auditorPk,
                true,
                &holderSk),
            Ter(temMALFORMED));

        env(convertJV(
                carol,
                mpt.issuanceID(),
                1,
                holderPk,
                issuerPk,
                r,
                auditorPk,
                true,
                &holderSk),
            Ter(tecOBJECT_NOT_FOUND));

        env(convertJV(
                bob,
                mpt.issuanceID(),
                101,
                holderPk,
                issuerPk,
                r,
                auditorPk,
                true,
                &holderSk),
            Ter(tecINSUFFICIENT_FUNDS));

        {
            auto jv = convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, auditorPk, true, &holderSk);
            jv[sfHolderEncryptedAmount] = "00";
            env(jv, Ter(temBAD_CIPHERTEXT));
        }

        {
            auto jv = convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, auditorPk, true, &holderSk);
            jv.removeMember(sfZKProof.jsonName);
            env(jv, Ter(temMALFORMED));
        }

        {
            auto jv = convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, auditorPk, false, nullptr);
            env(jv, Ter(tecNO_PERMISSION));
        }

        {
            auto jv = convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, std::nullopt, true, &holderSk);
            env(jv, Ter(tecNO_PERMISSION));
        }

        {
            auto const badR = scalarFromSecret(secpKeys("wrong-r").second);
            auto jv = convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, auditorPk, true, &holderSk);
            jv[sfBlindingFactor] = to_string(badR);
            env(jv, Ter(tecBAD_PROOF));
        }

        env(convertJV(
            bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, auditorPk, true, &holderSk));

        env(convertJV(
                bob,
                mpt.issuanceID(),
                5,
                holderPk,
                issuerPk,
                scalarFromSecret(secpKeys("blind-dup").second),
                auditorPk,
                true,
                &holderSk),
            Ter(tecDUPLICATE));

        env(convertJV(
            bob,
            mpt.issuanceID(),
            5,
            holderPk,
            issuerPk,
            scalarFromSecret(secpKeys("blind-2").second),
            auditorPk,
            false,
            nullptr));
    }

    void
    testNoConfidentialFlag(FeatureBitset features)
    {
        testcase("No confidential flag");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 50);

        auto const [holderPk, holderSk] = secpKeys("h-ncf");
        auto const issuerPk = secpKeys("i-ncf").first;
        auto const r = scalarFromSecret(secpKeys("r-ncf").second);
        env(convertJV(
                bob, mpt.issuanceID(), 1, holderPk, issuerPk, r, std::nullopt, true, &holderSk),
            Ter(tecNO_PERMISSION));
    }

    void
    testMergeErrors(FeatureBitset features)
    {
        testcase("Merge errors");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        auto const issuerPk = secpKeys("issuer-merge").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        env(mergeJV(bob, mpt.issuanceID()), Ter(tecNO_PERMISSION));
        env(mergeJV(alice, mpt.issuanceID()), Ter(temMALFORMED));

        auto const [holderPk, holderSk] = secpKeys("holder-merge");
        auto const r = scalarFromSecret(secpKeys("blind-merge").second);
        env(convertJV(
            bob, mpt.issuanceID(), 20, holderPk, issuerPk, r, std::nullopt, true, &holderSk));

        mpt.set({.holder = bob, .flags = tfMPTLock});
        env(mergeJV(bob, mpt.issuanceID()), Ter(tecLOCKED));
        mpt.set({.holder = bob, .flags = tfMPTUnlock});
        env(mergeJV(bob, mpt.issuanceID()));
    }

    void
    testConvertLockAndAuth(FeatureBitset features)
    {
        testcase("Convert lock and auth");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock |
                 tfMPTRequireAuth});
        auto const issuerPk = secpKeys("issuer-lockauth").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = alice, .holder = bob});
        mpt.pay(alice, bob, 100);

        auto const [holderPk, holderSk] = secpKeys("holder-lockauth");
        auto const r = scalarFromSecret(secpKeys("blind-lockauth").second);

        // Locked holders cannot convert public MPT, including zero-amount key registration.
        mpt.set({.holder = bob, .flags = tfMPTLock});
        env(convertJV(
                bob, mpt.issuanceID(), 0, holderPk, issuerPk, r, std::nullopt, true, &holderSk),
            Ter(tecLOCKED));
        env(convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, std::nullopt, true, &holderSk),
            Ter(tecLOCKED));
        mpt.set({.holder = bob, .flags = tfMPTUnlock});

        // Deauthorized holders cannot convert either.
        mpt.authorize({.account = alice, .holder = bob, .flags = tfMPTUnauthorize});
        env(convertJV(
                bob, mpt.issuanceID(), 0, holderPk, issuerPk, r, std::nullopt, true, &holderSk),
            Ter(tecNO_AUTH));
        env(convertJV(
                bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, std::nullopt, true, &holderSk),
            Ter(tecNO_AUTH));

        mpt.authorize({.account = alice, .holder = bob});
        env(convertJV(
            bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, std::nullopt, true, &holderSk));
    }

    void
    testFeeAndDelegate(FeatureBitset features)
    {
        testcase("Fee and delegate");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        env.fund(XRP(10'000), carol);
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("issuer-fee").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const [holderPk, holderSk] = secpKeys("holder-fee");
        auto const r = scalarFromSecret(secpKeys("blind-fee").second);
        auto jv = convertJV(
            bob, mpt.issuanceID(), 10, holderPk, issuerPk, r, std::nullopt, true, &holderSk);

        auto const base = env.current()->fees().base;
        env(jv, Fee(base), Ter(telINSUF_FEE_P));

        env(delegate::set(bob, carol, {"ConfidentialMPTConvert", "ConfidentialMPTMergeInbox"}));
        env(jv, delegate::As(carol));

        env(mergeJV(bob, mpt.issuanceID()), Fee(base), Ter(telINSUF_FEE_P));
        env(mergeJV(bob, mpt.issuanceID()), delegate::As(carol));
    }

    void
    testDeletionBlocker(FeatureBitset features)
    {
        testcase("Deletion blocker");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("issuer-del").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 50);

        auto const [holderPk, holderSk] = secpKeys("holder-del");
        auto const r = scalarFromSecret(secpKeys("blind-del").second);
        env(convertJV(
            bob, mpt.issuanceID(), 50, holderPk, issuerPk, r, std::nullopt, true, &holderSk));

        mpt.authorize({.account = bob, .flags = tfMPTUnauthorize, .err = tecHAS_OBLIGATIONS});
    }

    void
    testWithFeats(FeatureBitset features)
    {
        testDisabled(features);
        testConvertAndMerge(features);
        testZeroAmountOptIn(features);
        testConvertErrors(features);
        testNoConfidentialFlag(features);
        testMergeErrors(features);
        testConvertLockAndAuth(features);
        testFeeAndDelegate(features);
        testDeletionBlocker(features);
    }

public:
    void
    run() override
    {
        using namespace test::jtx;
        testWithFeats(testableAmendments() | featureConfidentialTransfer);
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvert, app, xrpl);

}  // namespace xrpl
