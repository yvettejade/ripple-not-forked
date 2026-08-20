#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/credentials.h>
#include <test/jtx/delegate.h>
#include <test/jtx/deposit.h>
#include <test/jtx/fee.h>
#include <test/jtx/flags.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/protocol/Confidential.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/Protocol.h>
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

class ConfidentialMPTSend_test : public beast::unit_test::suite
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
    mergeJV(Account const& account, MPTID const& mptId)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        return jv;
    }

    json::Value
    convertJV(
        Account const& account,
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
            auto const proof =
                schnorrProve(holderPk.slice(), skSlice(*holderSk), transcript);
            if (!BEAST_EXPECT(proof))
                return json::Value();
            jv[sfZKProof] = strHex(*proof);
        }
        return jv;
    }

    json::Value
    convertBackJV(
        test::jtx::Env& env,
        Account const& account,
        MPTID const& mptId,
        std::uint64_t amount,
        std::uint64_t balance,
        PublicKey const& holderPk,
        SecretKey const& holderSk,
        PublicKey const& issuerPk,
        std::optional<PublicKey> const& auditorPk,
        uint256 const& r,
        uint256 const& gamma)
    {
        auto const sle = env.le(keylet::mptoken(mptId, account));
        if (!BEAST_EXPECT(sle))
            return json::Value();
        Blob const spending = sle->getFieldVL(sfConfidentialBalanceSpending);
        auto const version = sle->getFieldU32(sfConfidentialBalanceVersion);
        auto const transcript = convertBackTranscript(account.id(), mptId, version);
        std::optional<Slice> aud;
        if (auditorPk)
            aud = auditorPk->slice();
        auto const proof = convertBackProve(
            holderPk.slice(),
            skSlice(holderSk),
            issuerPk.slice(),
            aud,
            makeSlice(spending),
            amount,
            balance,
            r,
            gamma,
            transcript);
        if (!BEAST_EXPECT(proof))
            return json::Value();

        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = strHex(proof->holderEnc);
        jv[sfIssuerEncryptedAmount] = strHex(proof->issuerEnc);
        jv[sfBlindingFactor] = to_string(r);
        jv[sfBalanceCommitment] = strHex(proof->balanceCommitment);
        jv[sfZKProof] = strHex(proof->zkProof);
        if (auditorPk)
            jv[sfAuditorEncryptedAmount] = strHex(proof->auditorEnc);
        return jv;
    }

    json::Value
    sendJV(
        test::jtx::Env& env,
        Account const& sender,
        Account const& dest,
        MPTID const& mptId,
        std::uint64_t amount,
        std::uint64_t balance,
        PublicKey const& senderPk,
        SecretKey const& senderSk,
        PublicKey const& destPk,
        PublicKey const& issuerPk,
        std::optional<PublicKey> const& auditorPk,
        uint256 const& r,
        uint256 const& gamma)
    {
        auto const sle = env.le(keylet::mptoken(mptId, sender));
        if (!BEAST_EXPECT(sle))
            return json::Value();
        Blob const spending = sle->getFieldVL(sfConfidentialBalanceSpending);
        auto const version = sle->getFieldU32(sfConfidentialBalanceVersion);
        auto const transcript = sendTranscript(sender.id(), dest.id(), mptId, version);
        std::optional<Slice> aud;
        if (auditorPk)
            aud = auditorPk->slice();
        auto const proof = sendProve(
            senderPk.slice(),
            skSlice(senderSk),
            destPk.slice(),
            issuerPk.slice(),
            aud,
            makeSlice(spending),
            amount,
            balance,
            r,
            gamma,
            transcript);
        if (!BEAST_EXPECT(proof))
            return json::Value();

        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTSend;
        jv[jss::Account] = sender.human();
        jv[jss::Destination] = dest.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        jv[sfSenderEncryptedAmount] = strHex(proof->senderEnc);
        jv[sfDestinationEncryptedAmount] = strHex(proof->destEnc);
        jv[sfIssuerEncryptedAmount] = strHex(proof->issuerEnc);
        jv[sfAmountCommitment] = strHex(proof->amountCommitment);
        jv[sfBalanceCommitment] = strHex(proof->balanceCommitment);
        jv[sfZKProof] = strHex(proof->zkProof);
        if (auditorPk)
            jv[sfAuditorEncryptedAmount] = strHex(proof->auditorEnc);
        return jv;
    }

    json::Value
    clawbackJV(
        test::jtx::Env& env,
        Account const& issuer,
        Account const& holder,
        MPTID const& mptId,
        std::uint64_t amount,
        PublicKey const& issuerPk,
        SecretKey const& issuerSk)
    {
        auto const sle = env.le(keylet::mptoken(mptId, holder));
        if (!BEAST_EXPECT(sle))
            return json::Value();
        Blob const issuerCt = sle->getFieldVL(sfIssuerEncryptedBalance);
        auto const transcript = clawbackTranscript(issuer.id(), holder.id(), mptId);
        auto const proof = clawbackProve(
            makeSlice(issuerCt), issuerPk.slice(), amount, skSlice(issuerSk), transcript);
        if (!BEAST_EXPECT(proof))
            return json::Value();

        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTClawback;
        jv[jss::Account] = issuer.human();
        jv[sfHolder] = holder.human();
        jv[sfMPTokenIssuanceID] = to_string(mptId);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfZKProof] = strHex(*proof);
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
        Account const carol("carol");
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer | tfMPTCanClawback});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 100);

        auto const [holderPk, holderSk] = secpKeys("dis-h");
        auto const [issuerPk, issuerSk] = secpKeys("dis-i");
        auto const destPk = secpKeys("dis-d").first;
        auto const r = scalarFromSecret(secpKeys("dis-r").second);
        auto const gamma = scalarFromSecret(secpKeys("dis-g").second);
        auto const spendR = scalarFromSecret(secpKeys("dis-sr").second);
        auto const spending = elgamalEncrypt(holderPk.slice(), 100, spendR);
        if (!BEAST_EXPECT(spending))
            return;

        auto const cb = convertBackProve(
            holderPk.slice(),
            skSlice(holderSk),
            issuerPk.slice(),
            std::nullopt,
            *spending,
            10,
            100,
            r,
            gamma,
            convertBackTranscript(bob.id(), mpt.issuanceID(), 0));
        if (!BEAST_EXPECT(cb))
            return;
        json::Value cbJv;
        cbJv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        cbJv[jss::Account] = bob.human();
        cbJv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
        cbJv[sfMPTAmount] = std::to_string(10);
        cbJv[sfHolderEncryptedAmount] = strHex(cb->holderEnc);
        cbJv[sfIssuerEncryptedAmount] = strHex(cb->issuerEnc);
        cbJv[sfBlindingFactor] = to_string(r);
        cbJv[sfBalanceCommitment] = strHex(cb->balanceCommitment);
        cbJv[sfZKProof] = strHex(cb->zkProof);
        env(cbJv, Ter(temDISABLED));

        auto const send = sendProve(
            holderPk.slice(),
            skSlice(holderSk),
            destPk.slice(),
            issuerPk.slice(),
            std::nullopt,
            *spending,
            10,
            100,
            r,
            gamma,
            sendTranscript(bob.id(), carol.id(), mpt.issuanceID(), 0));
        if (!BEAST_EXPECT(send))
            return;
        json::Value sendJv;
        sendJv[jss::TransactionType] = jss::ConfidentialMPTSend;
        sendJv[jss::Account] = bob.human();
        sendJv[jss::Destination] = carol.human();
        sendJv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
        sendJv[sfSenderEncryptedAmount] = strHex(send->senderEnc);
        sendJv[sfDestinationEncryptedAmount] = strHex(send->destEnc);
        sendJv[sfIssuerEncryptedAmount] = strHex(send->issuerEnc);
        sendJv[sfAmountCommitment] = strHex(send->amountCommitment);
        sendJv[sfBalanceCommitment] = strHex(send->balanceCommitment);
        sendJv[sfZKProof] = strHex(send->zkProof);
        env(sendJv, Ter(temDISABLED));

        auto const issuerCt = elgamalEncrypt(issuerPk.slice(), 100, spendR);
        if (!BEAST_EXPECT(issuerCt))
            return;
        auto const claw = clawbackProve(
            *issuerCt,
            issuerPk.slice(),
            100,
            skSlice(issuerSk),
            clawbackTranscript(alice.id(), bob.id(), mpt.issuanceID()));
        if (!BEAST_EXPECT(claw))
            return;
        json::Value clawJv;
        clawJv[jss::TransactionType] = jss::ConfidentialMPTClawback;
        clawJv[jss::Account] = alice.human();
        clawJv[sfHolder] = bob.human();
        clawJv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
        clawJv[sfMPTAmount] = std::to_string(100);
        clawJv[sfZKProof] = strHex(*claw);
        env(clawJv, Ter(temDISABLED));
    }

    void
    testSendConvertBackClawback(FeatureBitset features)
    {
        testcase("Send, convert-back, and clawback");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer |
                 tfMPTCanClawback | tfMPTCanLock});
        auto const [issuerPk, issuerSk] = secpKeys("iss-happy");
        auto const auditorPk = secpKeys("aud-happy").first;
        mpt.set(
            {.issuerEncryptionKey = strHex(issuerPk.slice()),
             .auditorEncryptionKey = strHex(auditorPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 1000);

        auto const [bobPk, bobSk] = secpKeys("bob-enc");
        auto const [carolPk, carolSk] = secpKeys("carol-enc");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            200,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("c1").second),
            auditorPk,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));
        env(convertJV(
            carol,
            mpt.issuanceID(),
            0,
            carolPk,
            issuerPk,
            scalarFromSecret(secpKeys("c0").second),
            auditorPk,
            true,
            &carolSk));

        auto const sleIss0 = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss0)[sfOutstandingAmount] == 1000);
        BEAST_EXPECT((*sleIss0)[sfConfidentialOutstandingAmount] == 200);
        BEAST_EXPECT((*env.le(keylet::mptoken(mpt.issuanceID(), bob)))[sfMPTAmount] == 800);

        env(sendJV(
            env,
            bob,
            carol,
            mpt.issuanceID(),
            50,
            200,
            bobPk,
            bobSk,
            carolPk,
            issuerPk,
            auditorPk,
            scalarFromSecret(secpKeys("s1").second),
            scalarFromSecret(secpKeys("g1").second)));

        auto const sleIss1 = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss1)[sfOutstandingAmount] == 1000);
        BEAST_EXPECT((*sleIss1)[sfConfidentialOutstandingAmount] == 200);
        BEAST_EXPECT(
            (*env.le(keylet::mptoken(mpt.issuanceID(), bob)))[sfConfidentialBalanceVersion] == 2);

        env(mergeJV(carol, mpt.issuanceID()));
        env(convertBackJV(
            env,
            carol,
            mpt.issuanceID(),
            50,
            50,
            carolPk,
            carolSk,
            issuerPk,
            auditorPk,
            scalarFromSecret(secpKeys("cb1").second),
            scalarFromSecret(secpKeys("gcb").second)));

        BEAST_EXPECT((*env.le(keylet::mptoken(mpt.issuanceID(), carol)))[sfMPTAmount] == 50);
        BEAST_EXPECT(
            (*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfConfidentialOutstandingAmount] ==
            150);

        env(clawbackJV(env, alice, bob, mpt.issuanceID(), 150, issuerPk, issuerSk));

        auto const sleIss2 = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss2)[sfConfidentialOutstandingAmount] == 0);
        BEAST_EXPECT((*sleIss2)[sfOutstandingAmount] == 850);
        auto const sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob));
        auto const zHolder = encZero(bob.id(), alice.id(), mpt.issuanceID(), bobPk.slice());
        auto const zIssuer = encZero(bob.id(), alice.id(), mpt.issuanceID(), issuerPk.slice());
        auto const zAud = encZero(bob.id(), alice.id(), mpt.issuanceID(), auditorPk.slice());
        BEAST_EXPECT(zHolder && zIssuer && zAud);
        BEAST_EXPECT(strHex((*sleBob)[sfConfidentialBalanceSpending]) == strHex(*zHolder));
        BEAST_EXPECT(strHex((*sleBob)[sfConfidentialBalanceInbox]) == strHex(*zHolder));
        BEAST_EXPECT(strHex((*sleBob)[sfIssuerEncryptedBalance]) == strHex(*zIssuer));
        BEAST_EXPECT(strHex((*sleBob)[sfAuditorEncryptedBalance]) == strHex(*zAud));
        BEAST_EXPECT((*sleBob)[sfMPTAmount] == 800);
    }

    void
    testSendErrors(FeatureBitset features)
    {
        testcase("Send errors");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Account const dave("dave");
        env.fund(XRP(10'000), dave);
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        auto const issuerPk = secpKeys("iss-err").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 500);

        auto const [bobPk, bobSk] = secpKeys("bob-err");
        auto const [carolPk, carolSk] = secpKeys("carol-err");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            100,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("ce1").second),
            std::nullopt,
            true,
            &bobSk));

        // Destination has not opted in.
        env(sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-noopt").second),
                scalarFromSecret(secpKeys("ge-noopt").second)),
            Ter(tecNO_PERMISSION));

        env(convertJV(
            carol,
            mpt.issuanceID(),
            0,
            carolPk,
            issuerPk,
            scalarFromSecret(secpKeys("ce0").second),
            std::nullopt,
            true,
            &carolSk));

        // Funds are still in the inbox until merge.
        env(sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-nomerge").second),
                scalarFromSecret(secpKeys("ge-nomerge").second)),
            Ter(tecBAD_PROOF));

        env(mergeJV(bob, mpt.issuanceID()));

        env(sendJV(
                env,
                bob,
                bob,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                bobPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-self").second),
                scalarFromSecret(secpKeys("ge-self").second)),
            Ter(temMALFORMED));

        {
            auto jv = sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-iss").second),
                scalarFromSecret(secpKeys("ge-iss").second));
            jv[jss::Account] = alice.human();
            env(jv, Ter(temMALFORMED));
        }

        env(sendJV(
                env,
                bob,
                dave,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-nompt").second),
                scalarFromSecret(secpKeys("ge-nompt").second)),
            Ter(tecOBJECT_NOT_FOUND));

        {
            auto jv = sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-aud").second),
                scalarFromSecret(secpKeys("ge-aud").second));
            auto const extra = elgamalEncrypt(
                secpKeys("extra-aud").first.slice(),
                10,
                scalarFromSecret(secpKeys("se-aud").second));
            if (BEAST_EXPECT(extra))
            {
                jv[sfAuditorEncryptedAmount] = strHex(*extra);
                env(jv, Ter(tecNO_PERMISSION));
            }
        }

        {
            auto jv = sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-bad").second),
                scalarFromSecret(secpKeys("ge-bad").second));
            auto proofHex = jv[sfZKProof].asString();
            proofHex[0] = proofHex[0] == '0' ? '1' : '0';
            jv[sfZKProof] = proofHex;
            env(jv, Ter(tecBAD_PROOF));
        }

        mpt.set({.holder = bob, .flags = tfMPTLock});
        env(sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                100,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("se-lock").second),
                scalarFromSecret(secpKeys("ge-lock").second)),
            Ter(tecLOCKED));
        mpt.set({.holder = bob, .flags = tfMPTUnlock});

        env(sendJV(
            env,
            bob,
            carol,
            mpt.issuanceID(),
            10,
            100,
            bobPk,
            bobSk,
            carolPk,
            issuerPk,
            std::nullopt,
            scalarFromSecret(secpKeys("se-ok").second),
            scalarFromSecret(secpKeys("ge-ok").second)));
    }

    void
    testConvertBackErrors(FeatureBitset features)
    {
        testcase("ConvertBack errors");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        auto const issuerPk = secpKeys("iss-cb").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 200);

        auto const [bobPk, bobSk] = secpKeys("bob-cb");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            80,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("cb-c").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));

        {
            json::Value jv;
            jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            jv[jss::Account] = bob.human();
            jv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            jv[sfMPTAmount] = std::to_string(0);
            jv[sfHolderEncryptedAmount] = std::string(132, '0');
            jv[sfIssuerEncryptedAmount] = std::string(132, '0');
            jv[sfBlindingFactor] = to_string(scalarFromSecret(secpKeys("cb-z").second));
            jv[sfBalanceCommitment] = strHex(bobPk.slice());
            jv[sfZKProof] = std::string(kConfidentialConvertBackZkLength * 2, '0');
            env(jv, Ter(temBAD_AMOUNT));
        }

        {
            auto jv = convertBackJV(
                env,
                bob,
                mpt.issuanceID(),
                10,
                80,
                bobPk,
                bobSk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("cb-iss").second),
                scalarFromSecret(secpKeys("cb-issg").second));
            jv[jss::Account] = alice.human();
            env(jv, Ter(temMALFORMED));
        }

        {
            auto jv = convertBackJV(
                env,
                bob,
                mpt.issuanceID(),
                10,
                80,
                bobPk,
                bobSk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("cb-over").second),
                scalarFromSecret(secpKeys("cb-overg").second));
            jv[sfMPTAmount] = std::to_string(81);
            env(jv, Ter(tecINSUFFICIENT_FUNDS));
        }

        mpt.set({.holder = bob, .flags = tfMPTLock});
        env(convertBackJV(
                env,
                bob,
                mpt.issuanceID(),
                10,
                80,
                bobPk,
                bobSk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("cb-lock").second),
                scalarFromSecret(secpKeys("cb-lockg").second)),
            Ter(tecLOCKED));
        mpt.set({.holder = bob, .flags = tfMPTUnlock});

        {
            auto jv = convertBackJV(
                env,
                bob,
                mpt.issuanceID(),
                10,
                80,
                bobPk,
                bobSk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("cb-bad").second),
                scalarFromSecret(secpKeys("cb-badg").second));
            auto proofHex = jv[sfZKProof].asString();
            proofHex[0] = proofHex[0] == '0' ? '1' : '0';
            jv[sfZKProof] = proofHex;
            env(jv, Ter(tecBAD_PROOF));
        }

        env(convertBackJV(
            env,
            bob,
            mpt.issuanceID(),
            10,
            80,
            bobPk,
            bobSk,
            issuerPk,
            std::nullopt,
            scalarFromSecret(secpKeys("cb-ok").second),
            scalarFromSecret(secpKeys("cb-okg").second)));
        BEAST_EXPECT((*env.le(keylet::mptoken(mpt.issuanceID(), bob)))[sfMPTAmount] == 130);
    }

    void
    testClawbackErrors(FeatureBitset features)
    {
        testcase("Clawback errors");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        env.fund(XRP(10'000), carol);
        MPTTester noClaw(env, alice, {.holders = {bob}});
        noClaw.create(
            {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const [issuerPk, issuerSk] = secpKeys("iss-cl");
        noClaw.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        noClaw.authorize({.account = bob});
        noClaw.pay(alice, bob, 50);
        auto const [bobPk, bobSk] = secpKeys("bob-cl");
        env(convertJV(
            bob,
            noClaw.issuanceID(),
            50,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("cl-c").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, noClaw.issuanceID()));

        env(clawbackJV(env, alice, bob, noClaw.issuanceID(), 50, issuerPk, issuerSk),
            Ter(tecNO_PERMISSION));

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 2,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback});
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 40);
        env(convertJV(
            bob,
            mpt.issuanceID(),
            40,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("cl-c2").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));

        {
            auto jv = clawbackJV(env, alice, bob, mpt.issuanceID(), 40, issuerPk, issuerSk);
            jv[jss::Account] = carol.human();
            env(jv, Ter(temMALFORMED));
        }
        {
            json::Value jv;
            jv[jss::TransactionType] = jss::ConfidentialMPTClawback;
            jv[jss::Account] = alice.human();
            jv[sfHolder] = alice.human();
            jv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            jv[sfMPTAmount] = std::to_string(40);
            jv[sfZKProof] = std::string(kConfidentialClawbackProofLength * 2, '0');
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = clawbackJV(env, alice, bob, mpt.issuanceID(), 40, issuerPk, issuerSk);
            jv[sfHolder] = carol.human();
            env(jv, Ter(tecOBJECT_NOT_FOUND));
        }
        env(clawbackJV(env, alice, bob, mpt.issuanceID(), 39, issuerPk, issuerSk),
            Ter(tecBAD_PROOF));

        env(clawbackJV(env, alice, bob, mpt.issuanceID(), 40, issuerPk, issuerSk));
        BEAST_EXPECT(
            (*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfConfidentialOutstandingAmount] ==
            0);
        BEAST_EXPECT((*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfOutstandingAmount] == 0);
    }

    void
    testNoTransfer(FeatureBitset features)
    {
        testcase("No CanTransfer");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});
        auto const issuerPk = secpKeys("iss-nt").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 30);

        auto const [bobPk, bobSk] = secpKeys("bob-nt");
        auto const [carolPk, carolSk] = secpKeys("carol-nt");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            30,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("nt-c").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));
        env(convertJV(
            carol,
            mpt.issuanceID(),
            0,
            carolPk,
            issuerPk,
            scalarFromSecret(secpKeys("nt-c0").second),
            std::nullopt,
            true,
            &carolSk));
        env(sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                5,
                30,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("nt-s").second),
                scalarFromSecret(secpKeys("nt-g").second)),
            Ter(tecNO_AUTH));
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
        Account const dave("dave");
        env.fund(XRP(10'000), dave);
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback});
        auto const [issuerPk, issuerSk] = secpKeys("iss-fee");
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 100);

        auto const [bobPk, bobSk] = secpKeys("bob-fee");
        auto const [carolPk, carolSk] = secpKeys("carol-fee");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            60,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("fee-c").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));
        env(convertJV(
            carol,
            mpt.issuanceID(),
            0,
            carolPk,
            issuerPk,
            scalarFromSecret(secpKeys("fee-c0").second),
            std::nullopt,
            true,
            &carolSk));

        auto const base = env.current()->fees().base;
        auto sendTx = sendJV(
            env,
            bob,
            carol,
            mpt.issuanceID(),
            20,
            60,
            bobPk,
            bobSk,
            carolPk,
            issuerPk,
            std::nullopt,
            scalarFromSecret(secpKeys("fee-s").second),
            scalarFromSecret(secpKeys("fee-g").second));
        env(sendTx, Fee(base), Ter(telINSUF_FEE_P));

        env(delegate::set(
            bob,
            dave,
            {"ConfidentialMPTSend", "ConfidentialMPTConvertBack", "ConfidentialMPTMergeInbox"}));
        env(sendTx, delegate::As(dave));

        env(mergeJV(carol, mpt.issuanceID()));
        auto back = convertBackJV(
            env,
            carol,
            mpt.issuanceID(),
            20,
            20,
            carolPk,
            carolSk,
            issuerPk,
            std::nullopt,
            scalarFromSecret(secpKeys("fee-cb").second),
            scalarFromSecret(secpKeys("fee-cbg").second));
        env(back, Fee(base), Ter(telINSUF_FEE_P));
        env(delegate::set(carol, dave, {"ConfidentialMPTConvertBack"}));
        env(back, delegate::As(dave));

        env(delegate::set(alice, dave, {"ConfidentialMPTClawback"}));
        auto claw = clawbackJV(env, alice, bob, mpt.issuanceID(), 40, issuerPk, issuerSk);
        env(claw, Fee(base), Ter(telINSUF_FEE_P));
        env(claw, delegate::As(dave));
    }

    void
    testDepositAuth(FeatureBitset features)
    {
        testcase("Deposit auth");
        using namespace test::jtx;

        Env env{*this, features};
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Account const credIssuer("credIssuer");
        env.fund(XRP(10'000), credIssuer);
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create(
            {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        auto const issuerPk = secpKeys("iss-da").first;
        mpt.set({.issuerEncryptionKey = strHex(issuerPk.slice())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 80);

        auto const [bobPk, bobSk] = secpKeys("bob-da");
        auto const [carolPk, carolSk] = secpKeys("carol-da");
        env(convertJV(
            bob,
            mpt.issuanceID(),
            80,
            bobPk,
            issuerPk,
            scalarFromSecret(secpKeys("da-c").second),
            std::nullopt,
            true,
            &bobSk));
        env(mergeJV(bob, mpt.issuanceID()));
        env(convertJV(
            carol,
            mpt.issuanceID(),
            0,
            carolPk,
            issuerPk,
            scalarFromSecret(secpKeys("da-c0").second),
            std::nullopt,
            true,
            &carolSk));

        env(fset(carol, asfDepositAuth));
        env(sendJV(
                env,
                bob,
                carol,
                mpt.issuanceID(),
                10,
                80,
                bobPk,
                bobSk,
                carolPk,
                issuerPk,
                std::nullopt,
                scalarFromSecret(secpKeys("da-s1").second),
                scalarFromSecret(secpKeys("da-g1").second)),
            Ter(tecNO_PERMISSION));

        env(deposit::auth(carol, bob));
        env(sendJV(
            env,
            bob,
            carol,
            mpt.issuanceID(),
            10,
            80,
            bobPk,
            bobSk,
            carolPk,
            issuerPk,
            std::nullopt,
            scalarFromSecret(secpKeys("da-s2").second),
            scalarFromSecret(secpKeys("da-g2").second)));
    }

    void
    testWithFeats(FeatureBitset features)
    {
        testDisabled(features);
        testSendConvertBackClawback(features);
        testSendErrors(features);
        testConvertBackErrors(features);
        testClawbackErrors(features);
        testNoTransfer(features);
        testFeeAndDelegate(features);
        testDepositAuth(features);
    }

public:
    void
    run() override
    {
        using namespace test::jtx;
        testWithFeats(testableAmendments() | featureConfidentialTransfer);
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSend, app, xrpl);

}  // namespace xrpl
