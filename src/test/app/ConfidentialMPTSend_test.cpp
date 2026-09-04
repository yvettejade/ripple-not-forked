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
#include <xrpl/crypto/Bulletproofs.h>
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
#include <xrpl/protocol/jss.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace xrpl {
namespace test {

class ConfidentialMPTSend_test : public beast::unit_test::Suite
{
    static constexpr char const* kKeyG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kScalar1 =
        "0000000000000000000000000000000000000000000000000000000000000001";
    static constexpr char const* kScalar2 =
        "0000000000000000000000000000000000000000000000000000000000000002";
    static constexpr std::size_t kSendZkProofSize = kSendSigmaSize + kAggregatedBulletproofSize;

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

    static std::string
    encryptHex(std::uint64_t amount, Secp256k1Point const& pk, Secp256k1Scalar const& r)
    {
        auto const ct = ElGamalCiphertext::encrypt(amount, pk, r);
        if (!ct)
            return {};
        return strHex(ct->serialize());
    }

    json::Value
    convertJV(
        jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        std::string const& holderCt,
        std::string const& issuerCt,
        std::string const& blinding,
        std::string const& holderKey,
        std::string const& zkProof)
    {
        json::Value jv;
        jv[jss::Account] = account.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTConvert;
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = holderCt;
        jv[sfIssuerEncryptedAmount] = issuerCt;
        jv[sfBlindingFactor] = blinding;
        jv[sfHolderEncryptionKey] = holderKey;
        jv[sfZKProof] = zkProof;
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

    json::Value
    sendJV(
        jtx::Account const& account,
        jtx::Account const& destination,
        MPTID const& issuanceID,
        std::string const& senderCt,
        std::string const& destCt,
        std::string const& issuerCt,
        std::string const& pcB,
        std::string const& pcM,
        std::string const& zk)
    {
        json::Value jv;
        jv[jss::Account] = account.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTSend;
        jv[jss::Destination] = destination.human();
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfSenderEncryptedAmount] = senderCt;
        jv[sfDestinationEncryptedAmount] = destCt;
        jv[sfIssuerEncryptedAmount] = issuerCt;
        jv[sfBalanceCommitment] = pcB;
        jv[sfAmountCommitment] = pcM;
        jv[sfZKProof] = zk;
        return jv;
    }

    static std::array<std::uint8_t, 24>
    sendSpecific(AccountID const& destination, std::uint32_t version)
    {
        std::array<std::uint8_t, 24> out{};
        std::memcpy(out.data(), destination.data(), 20);
        out[20] = static_cast<std::uint8_t>((version >> 24) & 0xff);
        out[21] = static_cast<std::uint8_t>((version >> 16) & 0xff);
        out[22] = static_cast<std::uint8_t>((version >> 8) & 0xff);
        out[23] = static_cast<std::uint8_t>(version & 0xff);
        return out;
    }

    void
    fundConvertMerge(
        jtx::Env& env,
        jtx::Account const& alice,
        jtx::Account const& holder,
        jtx::MPTTester& mpt,
        std::uint64_t amount,
        bool requireAuth = false)
    {
        using namespace jtx;
        // Caller creates issuance once; this only funds one holder.
        mpt.authorize({.account = holder});
        if (requireAuth)
            mpt.authorize({.account = alice, .holder = holder});
        if (amount > 0)
            mpt.pay(alice, holder, amount > 1000 ? amount : 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const holderCt = encryptHex(amount, *pk, *r);
        auto const issuerCt = encryptHex(amount, *pk, *r);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            holder.id(),
            mpt.issuanceID(),
            env.seq(holder));
        auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                holder,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok))),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(holder, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();
    }

    struct SendWitness
    {
        std::string senderCt;
        std::string destCt;
        std::string issuerCt;
        std::string pcBHex;
        std::string pcMHex;
        std::string zkHex;
    };

    std::optional<SendWitness>
    buildSendWitness(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& destination,
        MPTID const& issuanceID,
        std::uint64_t balance,
        std::uint64_t amount)
    {
        auto sleSender = env.le(keylet::mptoken(issuanceID, sender.id()));
        if (!sleSender)
            return std::nullopt;
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleSender->getFieldVL(sfConfidentialBalanceSpending)));
        if (!spending)
            return std::nullopt;
        auto const version = (*sleSender)[~sfConfidentialBalanceVersion].value_or(0);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar1);
        auto const rho = parseScalarHex(kScalar2);
        if (!sk || !pk || !r || !rho)
            return std::nullopt;

        // rem blind = ρ − r via field arithmetic.
        auto const remBlindField =
            fieldSub(Secp256k1Field::fromScalar(*rho), Secp256k1Field::fromScalar(*r));
        auto const remBlind = remBlindField.toScalar();
        if (!remBlind)
            return std::nullopt;

        auto const senderCt = ElGamalCiphertext::encrypt(amount, *pk, *r);
        auto const destCt = ElGamalCiphertext::encrypt(amount, *pk, *r);
        auto const issuerCt = ElGamalCiphertext::encrypt(amount, *pk, *r);
        if (!senderCt || !destCt || !issuerCt)
            return std::nullopt;

        auto const pcM = pedersenCommit(amount, *r);
        auto const pcB = pedersenCommit(balance, *rho);
        if (!pcM || !pcB)
            return std::nullopt;

        std::vector<Secp256k1Point> pks{*pk, *pk, *pk};
        std::vector<ElGamalCiphertext> cts{*senderCt, *destCt, *issuerCt};

        auto const specific = sendSpecific(destination.id(), version);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
            sender.id(),
            issuanceID,
            env.seq(sender),
            makeSlice(specific));

        auto const sigma = proveSendSigma(
            amount, *r, balance, *rho, *sk, pks, *pk, cts, *pcM, *pcB, *spending, makeSlice(ctxID));
        if (!sigma)
            return std::nullopt;

        auto const rem = balance - amount;
        auto const pcRem = pointSubtract(*pcB, *pcM);
        if (!pcRem)
            return std::nullopt;
        auto const bp = proveRange64Aggregated(amount, *r, *pcM, rem, *remBlind, *pcRem);
        if (!bp)
            return std::nullopt;

        std::array<std::uint8_t, kSendZkProofSize> zk{};
        std::memcpy(zk.data(), sigma->data(), kSendSigmaSize);
        std::memcpy(zk.data() + kSendSigmaSize, bp->data(), kAggregatedBulletproofSize);

        SendWitness w;
        w.senderCt = strHex(senderCt->serialize());
        w.destCt = strHex(destCt->serialize());
        w.issuerCt = strHex(issuerCt->serialize());
        w.pcBHex = strHex(pcB->serialize());
        w.pcMHex = strHex(pcM->serialize());
        w.zkHex = strHex(makeSlice(zk));
        return w;
    }

    void
    testHappyPath()
    {
        testcase("send after convert+merge");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, 100);
        // Charlie registers with amount 0 convert+merge (inbox initialized).
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const bobVersion = (*sleBob)[sfConfidentialBalanceVersion];
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const oa = (*sleIss)[sfOutstandingAmount];
        auto const coa = (*sleIss)[sfConfidentialOutstandingAmount];

        std::uint64_t const b = 100;
        std::uint64_t const m = 40;
        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), b, m);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto const baseFee = env.current()->fees().base;
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            Fee(10 * baseFee));
        env.close();

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == bobVersion + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) != spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) != inboxBefore);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oa);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coa);
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
        mpt.create({.flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});

        json::Value jv;
        jv[jss::Account] = bob.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTSend;
        jv[jss::Destination] = alice.human();
        jv[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
        jv[sfSenderEncryptedAmount] = std::string(132, '0');
        jv[sfDestinationEncryptedAmount] = std::string(132, '0');
        jv[sfIssuerEncryptedAmount] = std::string(132, '0');
        jv[sfBalanceCommitment] = std::string(kKeyG);
        jv[sfAmountCommitment] = std::string(kKeyG);
        jv[sfZKProof] = std::string(kSendZkProofSize * 2, '0');
        env(jv, Ter(temDISABLED));
    }

    void
    testSameAccount()
    {
        testcase("account equals destination");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 50);

        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar1);
        auto const ct = encryptHex(1, *pk, *r);
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                bob,
                mpt.issuanceID(),
                ct,
                ct,
                ct,
                std::string(kKeyG),
                std::string(kKeyG),
                std::string(kSendZkProofSize * 2, '0')),
            fee,
            Ter(temMALFORMED));
    }

    void
    testBadZkLength()
    {
        testcase("bad ZKProof length");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 50);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar1);
        auto const ct = encryptHex(1, *pk, *r);
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                ct,
                ct,
                ct,
                std::string(kKeyG),
                std::string(kKeyG),
                std::string(100, '0')),
            fee,
            Ter(temMALFORMED));
    }

    void
    testIssuerAsSender()
    {
        testcase("issuer as sender");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 50);

        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar1);
        auto const ct = encryptHex(1, *pk, *r);
        auto const fee = Fee(10 * env.current()->fees().base);
        // Issuer has no MPToken confidential fields → tecNO_PERMISSION
        // (spec gap: §8.3.1 temMALFORMED vs preclaim tec).
        env(sendJV(
                alice,
                bob,
                mpt.issuanceID(),
                ct,
                ct,
                ct,
                std::string(kKeyG),
                std::string(kKeyG),
                std::string(kSendZkProofSize * 2, '0')),
            fee,
            Ter(tecNO_PERMISSION));
    }

    void
    testNoCanTransfer()
    {
        testcase("no lsfMPTCanTransfer");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        // Confidential but not transferable.
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 50);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 50, 10);
        BEAST_EXPECT(w);
        if (!w)
            return;
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee,
            Ter(tecNO_AUTH));
    }

    void
    testTamperedProof()
    {
        testcase("tampered proof");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 100);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 25);
        BEAST_EXPECT(w);
        if (!w)
            return;
        // Flip one nibble in the sigma portion.
        if (w->zkHex.size() > 4)
            w->zkHex[3] = (w->zkHex[3] == '0') ? '1' : '0';

        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee,
            Ter(tecBAD_PROOF));
    }

    void
    testFeeMultiplier()
    {
        testcase("10x base fee");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 100);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto jv = sendJV(
            bob,
            charlie,
            mpt.issuanceID(),
            w->senderCt,
            w->destCt,
            w->issuerCt,
            w->pcBHex,
            w->pcMHex,
            w->zkHex);
        auto const baseFee = env.current()->fees().base;
        env(jv, Ter(telINSUF_FEE_P));
        env(jv, Fee(10 * baseFee));
        env.close();
    }

    void
    testDepositAuth()
    {
        testcase("deposit auth without preauth");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 100);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        env(fset(charlie, asfDepositAuth));
        env.close();

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 15);
        BEAST_EXPECT(w);
        if (!w)
            return;
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee,
            Ter(tecNO_PERMISSION));
    }

    void
    testRequireAuthSuccess()
    {
        testcase("RequireAuth: both authorized send succeeds");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, 100, true);
        fundConvertMerge(env, alice, charlie, mpt, 0, true);

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 25);
        BEAST_EXPECT(w);
        if (!w)
            return;
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee);
        env.close();
    }

    void
    testRequireAuthSenderRevoked()
    {
        // Holder converted while authorized cannot Send after being unauthorized.
        testcase("RequireAuth: sender revoked after convert");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, 100, true);
        fundConvertMerge(env, alice, charlie, mpt, 0, true);

        // Issuer revokes bob after he already holds confidential balance.
        mpt.authorize({.account = alice, .holder = bob, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(!mpt.checkFlags(lsfMPTAuthorized, bob));

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 20);
        BEAST_EXPECT(w);
        if (!w)
            return;
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee,
            Ter(tecNO_AUTH));
    }

    void
    testRequireAuthDestUnauthorized()
    {
        // Unauthorized destination cannot receive a confidential send.
        testcase("RequireAuth: destination unauthorized");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTRequireAuth});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, 100, true);
        fundConvertMerge(env, alice, charlie, mpt, 0, true);

        // Revoke destination after confidential init; sender remains authorized.
        mpt.authorize({.account = alice, .holder = charlie, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(mpt.checkFlags(lsfMPTAuthorized, bob));
        BEAST_EXPECT(!mpt.checkFlags(lsfMPTAuthorized, charlie));

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 20);
        BEAST_EXPECT(w);
        if (!w)
            return;
        auto const fee = Fee(10 * env.current()->fees().base);
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex),
            fee,
            Ter(tecNO_AUTH));
    }

public:
    void
    run() override
    {
        testHappyPath();
        testAmendmentDisabled();
        testSameAccount();
        testBadZkLength();
        testIssuerAsSender();
        testNoCanTransfer();
        testTamperedProof();
        testFeeMultiplier();
        testDepositAuth();
        testRequireAuthSuccess();
        testRequireAuthSenderRevoked();
        testRequireAuthDestUnauthorized();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSend, app, xrpl);

}  // namespace test
}  // namespace xrpl
