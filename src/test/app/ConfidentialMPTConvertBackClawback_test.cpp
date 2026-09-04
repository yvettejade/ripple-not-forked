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

class ConfidentialMPTConvertBackClawback_test : public beast::unit_test::Suite
{
    static constexpr char const* kKeyG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kScalar1 =
        "0000000000000000000000000000000000000000000000000000000000000001";
    static constexpr char const* kScalar2 =
        "0000000000000000000000000000000000000000000000000000000000000002";

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

    static std::array<std::uint8_t, 24>
    convertBackSpecific(AccountID const& account, std::uint32_t version)
    {
        std::array<std::uint8_t, 24> out{};
        std::memcpy(out.data(), account.data(), 20);
        out[20] = static_cast<std::uint8_t>((version >> 24) & 0xff);
        out[21] = static_cast<std::uint8_t>((version >> 16) & 0xff);
        out[22] = static_cast<std::uint8_t>((version >> 8) & 0xff);
        out[23] = static_cast<std::uint8_t>(version & 0xff);
        return out;
    }

    static std::array<std::uint8_t, 24>
    clawbackSpecific(AccountID const& holder)
    {
        std::array<std::uint8_t, 24> out{};
        std::memcpy(out.data(), holder.data(), 20);
        return out;
    }

    void
    fundConvertMerge(
        jtx::Env& env,
        jtx::Account const& alice,
        jtx::Account const& bob,
        jtx::MPTTester& mpt,
        std::uint64_t amount,
        std::uint32_t createFlags)
    {
        using namespace jtx;
        mpt.create({.ownerCount = 1, .flags = createFlags});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const r = parseScalarHex(kScalar2);
        auto const holderCt = encryptHex(amount, *pk, *r);
        auto const issuerCt = encryptHex(amount, *pk, *r);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            bob.id(),
            mpt.issuanceID(),
            env.seq(bob));
        auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                amount,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok))),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();
    }

    json::Value
    convertBackJV(
        jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        std::string const& holderCt,
        std::string const& issuerCt,
        std::string const& blinding,
        std::string const& pc,
        std::string const& zk)
    {
        json::Value jv;
        jv[jss::Account] = account.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = holderCt;
        jv[sfIssuerEncryptedAmount] = issuerCt;
        jv[sfBlindingFactor] = blinding;
        jv[sfBalanceCommitment] = pc;
        jv[sfZKProof] = zk;
        return jv;
    }

    json::Value
    clawbackJV(
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& issuanceID,
        std::uint64_t amount,
        std::string const& zk)
    {
        json::Value jv;
        jv[jss::Account] = issuer.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTClawback;
        jv[jss::Holder] = holder.human();
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfZKProof] = zk;
        return jv;
    }

    void
    testConvertBackHappy()
    {
        testcase("convert-back after merge");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env, alice, bob, mpt, 100, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(sk && pk && rho && rAmt);

        std::uint64_t const b = 100;
        std::uint64_t const m = 40;
        auto const pcB = pedersenCommit(b, *rho);
        BEAST_EXPECT(pcB);
        auto const specific = convertBackSpecific(bob.id(), version);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
            bob.id(),
            mpt.issuanceID(),
            env.seq(bob),
            makeSlice(specific));
        auto const sigma =
            proveConvertBackSigma(b, *rho, *sk, *pk, *spending, *pcB, makeSlice(ctxID));
        auto const pcRem = pointSubtract(*pcB, *generatorMultiply(Secp256k1Field::fromUint64(m)));
        BEAST_EXPECT(sigma && pcRem);
        auto const bp = proveRange64(b - m, *rho, *pcRem);
        BEAST_EXPECT(bp);

        std::array<std::uint8_t, kConvertBackSigmaSize + kSingleBulletproofSize> zk{};
        std::memcpy(zk.data(), sigma->data(), kConvertBackSigmaSize);
        std::memcpy(zk.data() + kConvertBackSigmaSize, bp->data(), kSingleBulletproofSize);

        auto const holderCt = encryptHex(m, *pk, *rAmt);
        auto const issuerCt = encryptHex(m, *pk, *rAmt);
        auto const baseFee = env.current()->fees().base;
        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                m,
                holderCt,
                issuerCt,
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(zk))),
            Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 940);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version + 1);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 60);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == 1000);
    }

    void
    testConvertBackDisabledAndZero()
    {
        testcase("convert-back disabled and amount 0");
        using namespace jtx;

        Env envOff{*this, withoutConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        envOff.fund(XRP(10000), alice, bob);
        envOff.close();
        MPTTester mptOff(envOff, alice, {.holders = {bob}, .fund = false});
        mptOff.create({.flags = tfMPTCanTransfer});
        mptOff.authorize({.account = bob});
        json::Value jv;
        jv[jss::Account] = bob.human();
        jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        jv[sfMPTokenIssuanceID] = to_string(mptOff.issuanceID());
        jv[sfMPTAmount] = "1";
        jv[sfHolderEncryptedAmount] = std::string(132, '0');
        jv[sfIssuerEncryptedAmount] = std::string(132, '0');
        jv[sfBlindingFactor] = kScalar1;
        jv[sfBalanceCommitment] = std::string(kKeyG);
        jv[sfZKProof] = std::string(1632, '0');
        envOff(jv, Ter(temDISABLED));

        Env env{*this, withConfidential()};
        env.fund(XRP(10000), alice, bob);
        env.close();
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env, alice, bob, mpt, 10, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);
        auto pk = parsePointHex(kKeyG);
        auto r = parseScalarHex(kScalar2);
        auto ct = encryptHex(0, *pk, *r);
        json::Value z = convertBackJV(
            bob, mpt.issuanceID(), 0, ct, ct, kScalar2, std::string(kKeyG), std::string(1632, '0'));
        env(z, Ter(temBAD_AMOUNT));
    }

    void
    testClawbackHappy()
    {
        testcase("clawback burns OA and COA");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env,
            alice,
            bob,
            mpt,
            100,
            tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const issuerCt =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
        BEAST_EXPECT(issuerCt);
        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const specific = clawbackSpecific(bob.id());
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
            alice.id(),
            mpt.issuanceID(),
            env.seq(alice),
            makeSlice(specific));
        auto const proof = proveClawbackSigma(100, *sk, *pk, *issuerCt, makeSlice(ctxID));
        BEAST_EXPECT(proof);

        auto const baseFee = env.current()->fees().base;
        env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
            Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 0);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == 900);
        auto const expectZero = encZero(bob.id(), alice.id(), mpt.issuanceID(), *pk);
        BEAST_EXPECT(
            strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == strHex(*expectZero));
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceInbox)) == strHex(*expectZero));
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == strHex(*expectZero));
    }

    void
    testClawbackFailures()
    {
        testcase("clawback failure paths");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env, alice, bob, mpt, 50, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto const fee = Fee(10 * env.current()->fees().base);
        env(clawbackJV(alice, alice, mpt.issuanceID(), 50, std::string(128, '0')),
            fee,
            Ter(temMALFORMED));
        env(clawbackJV(alice, bob, mpt.issuanceID(), 0, std::string(128, '0')),
            fee,
            Ter(temBAD_AMOUNT));
        env(clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(128, '0')),
            fee,
            Ter(tecNO_PERMISSION));
        env(clawbackJV(bob, alice, mpt.issuanceID(), 50, std::string(128, '0')),
            fee,
            Ter(tecNO_PERMISSION));
    }

    void
    run() override
    {
        testConvertBackHappy();
        testConvertBackDisabledAndZero();
        testClawbackHappy();
        testClawbackFailures();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvertBackClawback, app, xrpl);

}  // namespace test
}  // namespace xrpl
