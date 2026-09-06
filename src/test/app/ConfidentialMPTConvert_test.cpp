//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2026 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <test/jtx.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/jss.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace xrpl {
namespace test {

class ConfidentialMPTConvert_test : public beast::unit_test::Suite
{
    // secp256k1 G and 2G (compressed) — valid 33-byte points.
    static constexpr char const* kKeyG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kKey2G =
        "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
    // Scalar 1 and 2 (32-byte BE).
    static constexpr char const* kScalar1 =
        "0000000000000000000000000000000000000000000000000000000000000001";
    static constexpr char const* kScalar2 =
        "0000000000000000000000000000000000000000000000000000000000000002";
    // Non-scalar (>= n) used as a bad blinding factor.
    static constexpr char const* kScalarN =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    FeatureBitset
    withConfidential()
    {
        return jtx::testableAmendments() | featureConfidentialTransfer;
    }

    FeatureBitset
    withoutConfidential()
    {
        return jtx::testableAmendments() - featureConfidentialTransfer;
    }

    static std::optional<Secp256k1Scalar>
    parseScalarHex(char const* hex)
    {
        auto const bytes = strUnHex(hex);
        if (!bytes)
            return std::nullopt;
        return Secp256k1Scalar::parse(makeSlice(*bytes));
    }

    static std::optional<Secp256k1Point>
    parsePointHex(char const* hex)
    {
        auto const bytes = strUnHex(hex);
        if (!bytes)
            return std::nullopt;
        return Secp256k1Point::parse(makeSlice(*bytes));
    }

    // EncZero randomness r_z; canceling Convert uses bf = −r_z.
    static std::optional<Secp256k1Scalar>
    encZeroRandomness(AccountID const& account, AccountID const& issuer, MPTID const& issuanceID)
    {
        std::string msg = "EncZero";
        msg.append(reinterpret_cast<char const*>(account.data()), AccountID::kBytes);
        msg.append(reinterpret_cast<char const*>(issuer.data()), AccountID::kBytes);
        msg.append(reinterpret_cast<char const*>(issuanceID.data()), MPTID::kBytes);
        return hashToCurveScalar(makeSlice(msg));
    }

    static std::optional<Secp256k1Scalar>
    negateScalar(Secp256k1Scalar const& s)
    {
        return fieldNegate(Secp256k1Field::fromScalar(s)).toScalar();
    }

    static std::string
    scalarHex(Secp256k1Scalar const& s)
    {
        return strHex(s.serialize());
    }

    static std::string
    encryptHex(std::uint64_t amount, Secp256k1Point const& pk, Secp256k1Scalar const& r)
    {
        auto const ct = ElGamalCiphertext::encrypt(amount, pk, r);
        if (!ct)
            return {};
        return strHex(ct->serialize());
    }

    static std::string
    proofHex(
        Secp256k1Scalar const& sk,
        Secp256k1Point const& pk,
        AccountID const& account,
        MPTID const& issuanceID,
        std::uint32_t sequence)
    {
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT), account, issuanceID, sequence);
        auto const proof = proveRegisterPoK(sk, pk, makeSlice(ctxID));
        if (!proof)
            return {};
        return strHex(makeSlice(*proof));
    }

    json::Value
    convertJV(
        jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        std::string const& holderCt,
        std::string const& issuerCt,
        std::string const& blinding,
        std::optional<std::string> holderKey = std::nullopt,
        std::optional<std::string> zkProof = std::nullopt,
        std::optional<std::string> auditorCt = std::nullopt)
    {
        json::Value jv;
        jv[jss::Account] = account.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTConvert;
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = holderCt;
        jv[sfIssuerEncryptedAmount] = issuerCt;
        jv[sfBlindingFactor] = blinding;
        if (holderKey)
            jv[sfHolderEncryptionKey] = *holderKey;
        if (zkProof)
            jv[sfZKProof] = *zkProof;
        if (auditorCt)
            jv[sfAuditorEncryptedAmount] = *auditorCt;
        return jv;
    }

    json::Value
    mergeJV(jtx::Account const& account, MPTID const& issuanceID)
    {
        json::Value jv;
        jv[jss::Account] = account.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        return jv;
    }

    void
    testHappyPathAndMerge()
    {
        testcase("convert + merge happy path");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        auto const issuerPk = *pk;
        auto const holderPk = *pk;
        std::uint64_t const amount = 100;
        auto const holderCt = encryptHex(amount, holderPk, *r);
        auto const issuerCt = encryptHex(amount, issuerPk, *r);
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty());

        auto const seq = env.seq(bob);
        auto const proof = proofHex(*sk, holderPk, bob.id(), mpt.issuanceID(), seq);
        BEAST_EXPECT(!proof.empty());

        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                proof),
            Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 900);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(sleMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(sleMpt->isFieldPresent(sfIssuerEncryptedBalance));
        BEAST_EXPECT(sleMpt->isFieldPresent(sfConfidentialBalanceSpending));
        BEAST_EXPECT((*sleMpt)[~sfConfidentialBalanceVersion].value_or(0) == 0);

        auto const spending = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
        auto const expectZero = encZero(bob.id(), alice.id(), mpt.issuanceID(), holderPk);
        BEAST_EXPECT(expectZero);
        BEAST_EXPECT(strHex(spending) == strHex(*expectZero));

        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleIss);
        // ValidMPTPayment COA conservation (OA' = OA + Δpublic + ΔCOA):
        // public MPTAmount 1000→900 (Δpublic=-100), COA 0→100 (ΔCOA=+100),
        // OutstandingAmount unchanged at 1000. See Invariants_test
        // testConfidentialMPT positive ValidMPTPayment COA check.
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 100);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == 1000);

        // Convert amount 0 to register only is covered in a separate case;
        // here merge after convert.
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == 1);
        auto const inbox = sleMpt->getFieldVL(sfConfidentialBalanceInbox);
        BEAST_EXPECT(strHex(inbox) == strHex(*expectZero));

        // Merge again (no-op EncZero⊕EncZero): version 2.
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();
        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == 2);
    }

    void
    testRegisterOnly()
    {
        testcase("convert amount 0 register only");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 50);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        auto const holderCt = encryptHex(0, *pk, *r);
        auto const issuerCt = encryptHex(0, *pk, *r);
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const baseFee = env.current()->fees().base;

        env(convertJV(
                bob, mpt.issuanceID(), 0, holderCt, issuerCt, kScalar2, std::string(kKeyG), proof),
            Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 50);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfHolderEncryptionKey));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 0);
    }

    void
    testAmendmentDisabled()
    {
        testcase("amendment disabled");
        using namespace jtx;

        Env env{*this, withoutConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        // Without confidential fields the tx still fails temDISABLED before
        // deeper field checks — supply minimal valid-looking payloads.
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(1, *pk, *r);
        env(convertJV(bob, mpt.issuanceID(), 1, ct, ct, kScalar2), Ter(temDISABLED));
        env(mergeJV(bob, mpt.issuanceID()), Ter(temDISABLED));
    }

    void
    testIssuerConvertFails()
    {
        testcase("issuer convert fails");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(0, *pk, *r);
        auto const proof = proofHex(*sk, *pk, alice.id(), mpt.issuanceID(), env.seq(alice));
        auto const baseFee = env.current()->fees().base;

        // Spec: issuer Convert is invalid → tecNO_PERMISSION (checked before
        // MPToken existence).
        env(convertJV(alice, mpt.issuanceID(), 0, ct, ct, kScalar2, std::string(kKeyG), proof),
            Fee(10 * baseFee),
            Ter(tecNO_PERMISSION));

        env(mergeJV(alice, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecNO_PERMISSION));
    }

    void
    testBadProofAndBlinding()
    {
        testcase("bad proof / bad blinding");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(10, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        // Wrong proof bytes.
        std::string badProof(128, '0');
        env(convertJV(bob, mpt.issuanceID(), 10, ct, ct, kScalar2, std::string(kKeyG), badProof),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        // Blinding factor that is not a valid scalar.
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        env(convertJV(bob, mpt.issuanceID(), 10, ct, ct, kScalarN, std::string(kKeyG), proof),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        // Valid scalar but wrong reconstruct (encrypt with r=2, claim r=1).
        env(convertJV(
                bob,
                mpt.issuanceID(),
                10,
                ct,
                ct,
                kScalar1,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));
    }

    void
    testDuplicateKey()
    {
        testcase("duplicate holder key");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct0 = encryptHex(0, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        env(convertJV(
                bob,
                mpt.issuanceID(),
                0,
                ct0,
                ct0,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee));
        env.close();

        auto const ct = encryptHex(10, *pk, *r);
        env(convertJV(
                bob,
                mpt.issuanceID(),
                10,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecDUPLICATE));
    }

    void
    testInsufficientFunds()
    {
        testcase("insufficient funds");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 10);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(50, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        env(convertJV(
                bob,
                mpt.issuanceID(),
                50,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecINSUFFICIENT_FUNDS));
    }

    void
    testAuditorRequired()
    {
        testcase("auditor required missing");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .auditorEncryptionKey = kKey2G});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(10, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        env(convertJV(
                bob,
                mpt.issuanceID(),
                10,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecNO_PERMISSION));
    }

    void
    testDeleteBlocked()
    {
        testcase("delete MPToken after convert blocked");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        // Convert all public balance to confidential.
        auto const ct = encryptHex(100, *pk, *r);
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                100,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee));
        env.close();

        BEAST_EXPECT(mpt.checkMPTokenAmount(bob, 0));
        mpt.authorize({.account = bob, .flags = tfMPTUnauthorize, .err = tecHAS_OBLIGATIONS});
    }

    void
    testFeeMultiplier()
    {
        testcase("10x base fee");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const ct = encryptHex(1, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        auto jv = convertJV(
            bob,
            mpt.issuanceID(),
            1,
            ct,
            ct,
            kScalar2,
            std::string(kKeyG),
            proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob)));

        // Default autofill fee is 1× base → insufficient for 10× require.
        env(jv, Ter(telINSUF_FEE_P));

        // Same payload with explicit 10× succeeds.
        env(jv, Fee(10 * baseFee));
        env.close();
    }

    void
    testMergeFailurePaths()
    {
        testcase("merge inbox failure paths");
        using namespace jtx;

        // Issuer merge → tecNO_PERMISSION (also covered in testIssuerConvertFails).
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            auto const baseFee = env.current()->fees().base;
            env(mergeJV(alice, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecNO_PERMISSION));
        }

        // Amendment off merge → temDISABLED (also in testAmendmentDisabled).
        {
            Env env{*this, withoutConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.authorize({.account = bob});
            env(mergeJV(bob, mpt.issuanceID()), Ter(temDISABLED));
        }

        // Merge without confidential fields on the MPToken → tecNO_PERMISSION.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            mpt.authorize({.account = bob});
            mpt.pay(alice, bob, 100);
            // Bob never Converted — no inbox/spending/holder key.
            auto const baseFee = env.current()->fees().base;
            env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecNO_PERMISSION));
        }

        // Issuance locked → tecLOCKED.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create(
                {.ownerCount = 1,
                 .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            mpt.authorize({.account = bob});
            mpt.pay(alice, bob, 100);

            auto const sk = parseScalarHex(kScalar1);
            auto const pk = parsePointHex(kKeyG);
            auto const r = parseScalarHex(kScalar2);
            auto const ct = encryptHex(50, *pk, *r);
            auto const baseFee = env.current()->fees().base;
            env(convertJV(
                    bob,
                    mpt.issuanceID(),
                    50,
                    ct,
                    ct,
                    kScalar2,
                    std::string(kKeyG),
                    proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
                Fee(10 * baseFee));
            env.close();

            mpt.set({.flags = tfMPTLock});
            env.close();
            env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecLOCKED));
        }
    }

    void
    testHolderLocked()
    {
        testcase("holder MPToken locked rejects convert");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        // Lock holder MPToken only.
        mpt.set({.account = alice, .holder = bob, .flags = tfMPTLock});
        BEAST_EXPECT(env.le(keylet::mptoken(mpt.issuanceID(), bob.id()))->isFlag(lsfMPTLocked));
        BEAST_EXPECT(!env.le(keylet::mptIssuance(mpt.issuanceID()))->isFlag(lsfMPTLocked));

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);
        std::uint64_t const amount = 10;
        auto const ct = encryptHex(amount, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        auto const beforeMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const beforeIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const pubBefore = (*beforeMpt)[sfMPTAmount];
        auto const confBefore = (*beforeIss)[sfConfidentialOutstandingAmount];
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfIssuerEncryptedBalance));

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecLOCKED));
        env.close();

        auto const afterMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const afterIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*afterMpt)[sfMPTAmount] == pubBefore);
        BEAST_EXPECT((*afterIss)[sfConfidentialOutstandingAmount] == confBefore);
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfIssuerEncryptedBalance));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfConfidentialBalanceSpending));
    }

    void
    testIssuanceLocked()
    {
        testcase("issuance locked rejects convert");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 100);

        // Lock issuance only (holder token unlocked).
        mpt.set({.account = alice, .flags = tfMPTLock});
        BEAST_EXPECT(env.le(keylet::mptIssuance(mpt.issuanceID()))->isFlag(lsfMPTLocked));
        BEAST_EXPECT(!env.le(keylet::mptoken(mpt.issuanceID(), bob.id()))->isFlag(lsfMPTLocked));

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);
        std::uint64_t const amount = 10;
        auto const ct = encryptHex(amount, *pk, *r);
        auto const baseFee = env.current()->fees().base;

        auto const beforeMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const beforeIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const pubBefore = (*beforeMpt)[sfMPTAmount];
        auto const confBefore = (*beforeIss)[sfConfidentialOutstandingAmount];
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(!beforeMpt->isFieldPresent(sfIssuerEncryptedBalance));

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                ct,
                ct,
                kScalar2,
                std::string(kKeyG),
                proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
            Fee(10 * baseFee),
            Ter(tecLOCKED));
        env.close();

        auto const afterMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const afterIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*afterMpt)[sfMPTAmount] == pubBefore);
        BEAST_EXPECT((*afterIss)[sfConfidentialOutstandingAmount] == confBefore);
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfIssuerEncryptedBalance));
        BEAST_EXPECT(!afterMpt->isFieldPresent(sfConfidentialBalanceSpending));
    }

    void
    testUnauthorizedConvert()
    {
        // Holder is authorized, holds public balance; issuer unauthorizes.
        // Zero-amount key registration and value Convert both return tecNO_AUTH
        // with no confidential field or accounting mutation.
        testcase("unauthorized convert -> tecNO_AUTH");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = alice, .holder = bob});
        mpt.pay(alice, bob, 1000);
        mpt.authorize({.account = alice, .holder = bob, .flags = tfMPTUnauthorize});

        auto const sleTok = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleTok);
        BEAST_EXPECT(!sleTok->isFlag(lsfMPTAuthorized));
        BEAST_EXPECT((*sleTok)[sfMPTAmount] == 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);
        auto const baseFee = env.current()->fees().base;
        auto const fee = 10 * baseFee;

        auto assertUnchanged = [&]() {
            auto const sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto const sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sleMpt && sleIss);
            BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 1000);
            BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 0);
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfHolderEncryptionKey));
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfConfidentialBalanceInbox));
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfConfidentialBalanceSpending));
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfIssuerEncryptedBalance));
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfAuditorEncryptedBalance));
            BEAST_EXPECT(!sleMpt->isFieldPresent(sfConfidentialBalanceVersion));
        };

        {
            auto const ct = encryptHex(0, *pk, *r);
            BEAST_EXPECT(!ct.empty());
            env(convertJV(
                    bob,
                    mpt.issuanceID(),
                    0,
                    ct,
                    ct,
                    kScalar2,
                    std::string(kKeyG),
                    proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
                Fee(fee),
                Ter(tecNO_AUTH));
            assertUnchanged();
        }

        {
            std::uint64_t const amount = 50;
            auto const ct = encryptHex(amount, *pk, *r);
            BEAST_EXPECT(!ct.empty());
            env(convertJV(
                    bob,
                    mpt.issuanceID(),
                    amount,
                    ct,
                    ct,
                    kScalar2,
                    std::string(kKeyG),
                    proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob))),
                Fee(fee),
                Ter(tecNO_AUTH));
            assertUnchanged();
        }
    }

    void
    testM1ConvertEncZeroCancel()
    {
        // After first-init + merge, inbox is EncZero. Convert with bf = −r_EncZero
        // makes EncZero ⊕ C unrepresentable → fee-claiming tecINTERNAL.
        testcase("M1 convert EncZero cancel -> tecINTERNAL");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        auto const baseFee = env.current()->fees().base;
        auto const proof1 = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const holderCt1 = encryptHex(100, *pk, *r);
        auto const issuerCt1 = encryptHex(100, *pk, *r);
        BEAST_EXPECT(!proof1.empty() && !holderCt1.empty() && !issuerCt1.empty());

        env(convertJV(
                bob,
                mpt.issuanceID(),
                100,
                holderCt1,
                issuerCt1,
                scalarHex(*r),
                std::string(kKeyG),
                proof1),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        auto const rZ = encZeroRandomness(bob.id(), alice.id(), mpt.issuanceID());
        BEAST_EXPECT(rZ);
        auto const bf = negateScalar(*rZ);
        BEAST_EXPECT(bf);

        std::uint64_t const amount = 50;
        auto const holderCt = encryptHex(amount, *pk, *bf);
        auto const issuerCt = encryptHex(amount, *pk, *bf);
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty());

        auto const sleBefore = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIssBefore = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleBefore && sleIssBefore);
        auto const inboxBefore = sleBefore->getFieldVL(sfConfidentialBalanceInbox);
        auto const spendingBefore = sleBefore->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerCtBefore = sleBefore->getFieldVL(sfIssuerEncryptedBalance);
        auto const confBefore = (*sleIssBefore)[sfConfidentialOutstandingAmount];
        auto const balBefore = env.balance(bob);
        auto const seqBefore = env.seq(bob);
        auto const fee = 10 * baseFee;

        env(convertJV(bob, mpt.issuanceID(), amount, holderCt, issuerCt, scalarHex(*bf)),
            Fee(fee),
            Ter(tecINTERNAL));

        BEAST_EXPECT(env.balance(bob) == balBefore - fee);
        BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
        auto const sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleMpt && sleIss);
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 900);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == confBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(sleMpt->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
        BEAST_EXPECT(sleMpt->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleMpt->getFieldVL(sfIssuerEncryptedBalance) == issuerCtBefore);
    }

    void
    testM1MergeSpendingInboxCancel()
    {
        // First-init direct assign: Convert with bf = −r_EncZero succeeds
        // (inbox = C). Merge spending(r_z) ⊕ inbox(−r_z) → tecINTERNAL.
        testcase("M1 merge spending+inbox cancel -> tecINTERNAL");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        BEAST_EXPECT(sk && pk);

        auto const rZ = encZeroRandomness(bob.id(), alice.id(), mpt.issuanceID());
        BEAST_EXPECT(rZ);
        auto const bf = negateScalar(*rZ);
        BEAST_EXPECT(bf);

        std::uint64_t const amount = 100;
        auto const holderCt = encryptHex(amount, *pk, *bf);
        auto const issuerCt = encryptHex(amount, *pk, *bf);
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const baseFee = env.current()->fees().base;
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty() && !proof.empty());

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                scalarHex(*bf),
                std::string(kKeyG),
                proof),
            Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(sleMpt->isFieldPresent(sfConfidentialBalanceSpending));
        auto const inboxBefore = sleMpt->getFieldVL(sfConfidentialBalanceInbox);
        auto const spendingBefore = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerBefore = sleMpt->getFieldVL(sfIssuerEncryptedBalance);

        auto const balBefore = env.balance(bob);
        auto const seqBefore = env.seq(bob);
        auto const fee = 10 * baseFee;
        env(mergeJV(bob, mpt.issuanceID()), Fee(fee), Ter(tecINTERNAL));
        BEAST_EXPECT(env.balance(bob) == balBefore - fee);
        BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT((*sleMpt)[~sfConfidentialBalanceVersion].value_or(0) == 0);
        BEAST_EXPECT(sleMpt->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
        BEAST_EXPECT(sleMpt->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleMpt->getFieldVL(sfIssuerEncryptedBalance) == issuerBefore);
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 900);
    }

    void
    testUnauthorizedMergeInbox()
    {
        // Holder is authorized, converts to inbox; issuer unauthorizes before
        // merge. MergeInbox returns tecNO_AUTH with no state mutation.
        testcase("unauthorized merge inbox -> tecNO_AUTH");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = alice, .holder = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        std::uint64_t const amount = 100;
        auto const holderCt = encryptHex(amount, *pk, *r);
        auto const issuerCt = encryptHex(amount, *pk, *r);
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const baseFee = env.current()->fees().base;
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty() && !proof.empty());

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                proof),
            Fee(10 * baseFee));
        env.close();

        mpt.authorize({.account = alice, .holder = bob, .flags = tfMPTUnauthorize});
        auto const sleTok = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleTok);
        BEAST_EXPECT(!sleTok->isFlag(lsfMPTAuthorized));

        auto const sleBefore = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIssBefore = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleBefore && sleIssBefore);
        auto const inboxBefore = sleBefore->getFieldVL(sfConfidentialBalanceInbox);
        auto const spendingBefore = sleBefore->getFieldVL(sfConfidentialBalanceSpending);
        auto const versionBefore = (*sleBefore)[~sfConfidentialBalanceVersion].value_or(0);
        auto const coaBefore = (*sleIssBefore)[sfConfidentialOutstandingAmount];

        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecNO_AUTH));
        env.close();

        auto const sleAfter = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIssAfter = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleAfter && sleIssAfter);
        BEAST_EXPECT(sleAfter->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
        BEAST_EXPECT(sleAfter->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT((*sleAfter)[~sfConfidentialBalanceVersion].value_or(0) == versionBefore);
        BEAST_EXPECT((*sleIssAfter)[sfConfidentialOutstandingAmount] == coaBefore);
    }

    void
    testDomainAuthMergeInbox()
    {
        // Domain credential authorizes without lsfMPTAuthorized: Convert then
        // MergeInbox succeed (canonical requireAuth, not the old flag check).
        testcase("domain auth merge inbox success");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const credIssuer{"credIssuer"};
        env.fund(XRP(10000), alice, bob, credIssuer);
        env.close();

        std::string const credType = "credential";
        auto const domainId = [&]() {
            pdomain::Credentials const credentials{{.issuer = credIssuer, .credType = credType}};
            env(pdomain::setTx(credIssuer, credentials));
            return pdomain::getNewDomain(env.meta());
        }();
        env(credentials::create(bob, credIssuer, credType));
        env(credentials::accept(bob, credIssuer, credType));
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth,
             .domainID = domainId});
        BEAST_EXPECT(mpt.checkDomainID(domainId));
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        // Holder creates MPToken only — never receives lsfMPTAuthorized.
        mpt.authorize({.account = bob});
        {
            auto const sleTok = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            BEAST_EXPECT(sleTok);
            BEAST_EXPECT(!sleTok->isFlag(lsfMPTAuthorized));
        }
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        std::uint64_t const amount = 100;
        auto const holderCt = encryptHex(amount, *pk, *r);
        auto const issuerCt = encryptHex(amount, *pk, *r);
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const baseFee = env.current()->fees().base;
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty() && !proof.empty());

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                proof),
            Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(!sleMpt->isFlag(lsfMPTAuthorized));
        BEAST_EXPECT((*sleMpt)[~sfConfidentialBalanceVersion].value_or(0) == 0);
        auto const spendingBefore = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
        auto const expectZero = encZero(bob.id(), alice.id(), mpt.issuanceID(), *pk);
        BEAST_EXPECT(expectZero);
        BEAST_EXPECT(strHex(spendingBefore) == strHex(*expectZero));

        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(!sleMpt->isFlag(lsfMPTAuthorized));
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceInbox)) == strHex(*expectZero));
        // Spending absorbed inbox (homomorphic sum); no longer EncZero. Byte
        // equality with prior inbox is not required — EncZero⊕C may rescale.
        BEAST_EXPECT(sleMpt->getFieldVL(sfConfidentialBalanceSpending) != spendingBefore);
        BEAST_EXPECT(
            strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) != strHex(*expectZero));
    }

    void
    testDomainAuthMergeInboxReject()
    {
        // Convert succeeds via domain credential; credential deleted before
        // merge → tecNO_AUTH and no inbox/spending/version/COA mutation.
        testcase("domain auth merge inbox missing credential -> tecNO_AUTH");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const credIssuer{"credIssuer"};
        env.fund(XRP(10000), alice, bob, credIssuer);
        env.close();

        std::string const credType = "credential";
        auto const domainId = [&]() {
            pdomain::Credentials const credentials{{.issuer = credIssuer, .credType = credType}};
            env(pdomain::setTx(credIssuer, credentials));
            return pdomain::getNewDomain(env.meta());
        }();
        env(credentials::create(bob, credIssuer, credType));
        env(credentials::accept(bob, credIssuer, credType));
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth,
             .domainID = domainId});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        BEAST_EXPECT(
            !env.le(keylet::mptoken(mpt.issuanceID(), bob.id()))->isFlag(lsfMPTAuthorized));
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && r);

        std::uint64_t const amount = 50;
        auto const holderCt = encryptHex(amount, *pk, *r);
        auto const issuerCt = encryptHex(amount, *pk, *r);
        auto const proof = proofHex(*sk, *pk, bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const baseFee = env.current()->fees().base;
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty() && !proof.empty());

        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                proof),
            Fee(10 * baseFee));
        env.close();

        env(credentials::deleteCred(credIssuer, bob, credIssuer, credType));
        env.close();

        auto const sleBefore = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIssBefore = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleBefore && sleIssBefore);
        BEAST_EXPECT(!sleBefore->isFlag(lsfMPTAuthorized));
        auto const inboxBefore = sleBefore->getFieldVL(sfConfidentialBalanceInbox);
        auto const spendingBefore = sleBefore->getFieldVL(sfConfidentialBalanceSpending);
        auto const versionBefore = (*sleBefore)[~sfConfidentialBalanceVersion].value_or(0);
        auto const coaBefore = (*sleIssBefore)[sfConfidentialOutstandingAmount];

        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee), Ter(tecNO_AUTH));
        env.close();

        auto const sleAfter = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const sleIssAfter = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleAfter && sleIssAfter);
        BEAST_EXPECT(sleAfter->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
        BEAST_EXPECT(sleAfter->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT((*sleAfter)[~sfConfidentialBalanceVersion].value_or(0) == versionBefore);
        BEAST_EXPECT((*sleIssAfter)[sfConfidentialOutstandingAmount] == coaBefore);
    }

public:
    void
    run() override
    {
        testHappyPathAndMerge();
        testRegisterOnly();
        testAmendmentDisabled();
        testIssuerConvertFails();
        testBadProofAndBlinding();
        testDuplicateKey();
        testInsufficientFunds();
        testAuditorRequired();
        testDeleteBlocked();
        testFeeMultiplier();
        testMergeFailurePaths();
        testHolderLocked();
        testIssuanceLocked();
        testUnauthorizedConvert();
        testM1ConvertEncZeroCancel();
        testM1MergeSpendingInboxCancel();
        testUnauthorizedMergeInbox();
        testDomainAuthMergeInbox();
        testDomainAuthMergeInboxReject();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvert, app, xrpl);

}  // namespace test
}  // namespace xrpl
