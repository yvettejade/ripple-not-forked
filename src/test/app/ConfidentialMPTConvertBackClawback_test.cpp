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
#include <test/jtx/ConfidentialProofHarness.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/Bulletproofs.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/detail/STVar.h>
#include <xrpl/protocol/jss.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace xrpl {
namespace test {

class ConfidentialMPTConvertBackClawback_test : public beast::unit_test::Suite
{
    static constexpr char const* kKeyG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    // Compressed 2·G — distinct auditor public key.
    static constexpr char const* kKey2G =
        "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
    // Compressed 3·G — distinct issuer public key (holder uses 1·G).
    static constexpr char const* kKey3G =
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
    static constexpr char const* kScalar1 =
        "0000000000000000000000000000000000000000000000000000000000000001";
    static constexpr char const* kScalar2 =
        "0000000000000000000000000000000000000000000000000000000000000002";
    static constexpr char const* kScalar3 =
        "0000000000000000000000000000000000000000000000000000000000000003";

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
        std::string const& zkProof,
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
        jv[sfHolderEncryptionKey] = holderKey;
        jv[sfZKProof] = zkProof;
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

    static std::array<std::uint8_t, 24>
    convertBackSpecific(AccountID const& account, std::uint32_t version)
    {
        return jtx::cmpt::encodeConvertBackTxSpecific(account, version);
    }

    static std::array<std::uint8_t, 24>
    clawbackSpecific(AccountID const& holder)
    {
        return jtx::cmpt::encodeClawbackTxSpecific(holder);
    }

    /** EncZero randomness: H("EncZero" || account || issuer || issuanceID). */
    static std::optional<Secp256k1Scalar>
    encZeroRandomness(AccountID const& account, AccountID const& issuer, MPTID const& issuanceID)
    {
        std::vector<std::uint8_t> msg;
        constexpr char const tag[] = {'E', 'n', 'c', 'Z', 'e', 'r', 'o'};
        msg.reserve(sizeof(tag) + AccountID::kBytes + AccountID::kBytes + MPTID::kBytes);
        msg.insert(msg.end(), tag, tag + sizeof(tag));
        msg.insert(msg.end(), account.data(), account.data() + AccountID::kBytes);
        msg.insert(msg.end(), issuer.data(), issuer.data() + AccountID::kBytes);
        msg.insert(msg.end(), issuanceID.data(), issuanceID.data() + MPTID::kBytes);
        return hashToCurveScalar(makeSlice(msg));
    }

    static std::optional<Secp256k1Scalar>
    fieldToScalar(Secp256k1Field const& f)
    {
        return f.toScalar();
    }

    /** Build ConvertBack sigma||bulletproof for balance b converting amount m. */
    std::optional<std::array<std::uint8_t, kConvertBackSigmaSize + kSingleBulletproofSize>>
    makeConvertBackZk(
        std::uint64_t b,
        std::uint64_t m,
        Secp256k1Scalar const& rho,
        Secp256k1Scalar const& sk,
        Secp256k1Point const& pk,
        ElGamalCiphertext const& spending,
        AccountID const& account,
        MPTID const& issuanceID,
        std::uint32_t version,
        std::uint32_t seq)
    {
        auto const pcB = pedersenCommit(b, rho);
        if (!pcB)
            return std::nullopt;
        auto const ctxID = jtx::cmpt::convertBackContextID(account, issuanceID, seq, version);
        auto const sigma = proveConvertBackSigma(b, rho, sk, pk, spending, *pcB, makeSlice(ctxID));
        auto const mG = generatorMultiply(Secp256k1Field::fromUint64(m));
        if (!sigma || !mG)
            return std::nullopt;
        auto const pcRem = pointSubtract(*pcB, *mG);
        if (!pcRem)
            return std::nullopt;
        auto const bp = proveRange64(b - m, rho, *pcRem);
        if (!bp)
            return std::nullopt;
        return jtx::cmpt::spliceConvertBackZk(*sigma, *bp);
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
        auto const ctxID = jtx::cmpt::convertContextID(bob.id(), mpt.issuanceID(), env.seq(bob));
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
        std::string const& zk,
        std::optional<std::string> auditorCt = std::nullopt)
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
        if (auditorCt)
            jv[sfAuditorEncryptedAmount] = *auditorCt;
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
    testConvertBackUnrepresentableSubtraction()
    {
        testcase("convert-back rejects amount CT equal to stored balance");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        std::uint64_t const bal = 100;
        fundConvertMerge(
            env, alice, bob, mpt, bal, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spendingBlob = sleMpt->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerBlob = sleMpt->getFieldVL(sfIssuerEncryptedBalance);
        auto const spendingHex = strHex(spendingBlob);
        auto const issuerHex = strHex(issuerBlob);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        auto const rConvert = parseScalarHex(kScalar2);
        auto const rZero = encZeroRandomness(bob.id(), alice.id(), mpt.issuanceID());
        BEAST_EXPECT(sk && pk && rho && rConvert && rZero);

        // After convert+merge (#16 first-write): inbox = Enc(bal, rConvert),
        // spending was EncZero → merged spending = Enc(bal, rZero + rConvert).
        auto const spendR = fieldToScalar(
            fieldAdd(Secp256k1Field::fromScalar(*rZero), Secp256k1Field::fromScalar(*rConvert)));
        BEAST_EXPECT(spendR);
        BEAST_EXPECT(encryptHex(bal, *pk, *spendR) == spendingHex);

        auto const spending = parseElGamalCiphertext(makeSlice(spendingBlob));
        BEAST_EXPECT(spending);
        auto const zk = makeConvertBackZk(
            bal, bal, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);

        auto const baseFee = env.current()->fees().base;
        // Valid proof, but holder/issuer amount CTs equal stored spending →
        // spending ⊖ amount is the point at infinity.
        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                bal,
                spendingHex,
                spendingHex,
                strHex(spendR->serialize()),
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk))),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);

        // Issuer-mirror equality: first-write issuer CT = Enc(bal, rConvert).
        auto const issuerR = rConvert;
        BEAST_EXPECT(encryptHex(bal, *pk, *issuerR) == issuerHex);
        auto const zkIssuer = makeConvertBackZk(
            bal, bal, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zkIssuer);
        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                bal,
                issuerHex,
                issuerHex,
                strHex(issuerR->serialize()),
                strHex(pcB->serialize()),
                strHex(makeSlice(*zkIssuer))),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
    }

    void
    testConvertBackFullAmountDifferentRandomness()
    {
        testcase("convert-back full amount with distinct amount CT randomness");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        std::uint64_t const bal = 100;
        fundConvertMerge(
            env, alice, bob, mpt, bal, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        // Distinct from convert/merge randomness so Enc(bal, rAmt) ≠ stored CTs.
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(sk && pk && rho && rAmt);
        BEAST_EXPECT(
            encryptHex(bal, *pk, *rAmt) !=
            strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));

        auto const zk = makeConvertBackZk(
            bal, bal, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);

        auto const holderCt = encryptHex(bal, *pk, *rAmt);
        auto const issuerCt = encryptHex(bal, *pk, *rAmt);
        auto const baseFee = env.current()->fees().base;
        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                bal,
                holderCt,
                issuerCt,
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk))),
            Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 1000);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 0);
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
    testConvertBackAuditorMirrorAbsent()
    {
        testcase("convert-back rejects missing auditor mirror");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        std::uint64_t const bal = 50;
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .auditorEncryptionKey = kKey2G});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const auditorPk = parsePointHex(kKey2G);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && auditorPk && r);
        auto const holderCt = encryptHex(bal, *pk, *r);
        auto const issuerCt = encryptHex(bal, *pk, *r);
        auto const auditorCt = encryptHex(bal, *auditorPk, *r);
        auto const ctxID = jtx::cmpt::convertContextID(bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                bal,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok)),
                auditorCt),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfAuditorEncryptedBalance));
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);

        // Drop auditor mirror while issuance still requires auditor amounts.
        // Do not env.close() before ConvertBack — close rebuilds the open ledger.
        auto const stripped = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), bob.id()));
            if (!sle)
                return false;
            auto replacement = std::make_shared<SLE>(*sle, sle->key());
            replacement->makeFieldAbsent(sfAuditorEncryptedBalance);
            view.rawReplace(replacement);
            return true;
        });
        BEAST_EXPECT(stripped);
        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt && !sleMpt->isFieldPresent(sfAuditorEncryptedBalance));

        auto const rho = parseScalarHex(kScalar2);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rho && rAmt);
        auto const zk = makeConvertBackZk(
            bal, bal, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);

        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                bal,
                encryptHex(bal, *pk, *rAmt),
                encryptHex(bal, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)),
                encryptHex(bal, *auditorPk, *rAmt)),
            Fee(10 * baseFee),
            Ter(tecNO_PERMISSION));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT(!sleMpt->isFieldPresent(sfAuditorEncryptedBalance));
    }

    void
    testConvertBackAuditorUnrepresentableSubtraction()
    {
        testcase("convert-back rejects amount CT equal to auditor mirror");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        std::uint64_t const bal = 50;
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .auditorEncryptionKey = kKey2G});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const auditorPk = parsePointHex(kKey2G);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && auditorPk && r);
        auto const holderCt = encryptHex(bal, *pk, *r);
        auto const issuerCt = encryptHex(bal, *pk, *r);
        auto const auditorCt = encryptHex(bal, *auditorPk, *r);
        auto const ctxID = jtx::cmpt::convertContextID(bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                bal,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok)),
                auditorCt),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfAuditorEncryptedBalance));
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);

        // Amount CTs use distinct randomness so spending/issuer subs succeed;
        // surgically set auditor mirror equal to the submitted auditor amount CT.
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rAmt);
        auto const amtAuditorHex = encryptHex(bal, *auditorPk, *rAmt);
        auto const bytes = strUnHex(amtAuditorHex);
        BEAST_EXPECT(bytes);
        auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), bob.id()));
            if (!sle)
                return false;
            auto replacement = std::make_shared<SLE>(*sle, sle->key());
            replacement->setFieldVL(sfAuditorEncryptedBalance, *bytes);
            view.rawReplace(replacement);
            return true;
        });
        BEAST_EXPECT(ok);

        auto const rho = parseScalarHex(kScalar2);
        BEAST_EXPECT(rho);
        auto const zk = makeConvertBackZk(
            bal, bal, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);

        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                bal,
                encryptHex(bal, *pk, *rAmt),
                encryptHex(bal, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)),
                amtAuditorHex),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
    }

    void
    testUnauthorizedConvertBack()
    {
        // Holder converts while authorized, then is unauthorized; ConvertBack
        // must return tecNO_AUTH with public and confidential state unchanged.
        testcase("unauthorized convert-back -> tecNO_AUTH");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        std::uint64_t const bal = 100;
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
        auto const holderCt = encryptHex(bal, *pk, *r);
        auto const issuerCt = encryptHex(bal, *pk, *r);
        auto const ctxID = jtx::cmpt::convertContextID(bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                bal,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok))),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        mpt.authorize({.account = alice, .holder = bob, .flags = tfMPTUnauthorize});

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(!sleMpt->isFlag(lsfMPTAuthorized));
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spendingHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending));
        auto const issuerHex = strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];
        auto const oaBefore = (*sleIss)[sfOutstandingAmount];

        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const rho = parseScalarHex(kScalar2);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rho && rAmt);
        auto const zk = makeConvertBackZk(
            bal, 40, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);

        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                40,
                encryptHex(40, *pk, *rAmt),
                encryptHex(40, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk))),
            Fee(10 * baseFee),
            Ter(tecNO_AUTH));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaBefore);
    }

    void
    testConvertBackBulletproofTamper()
    {
        // Valid compact sigma prefix; corrupt only a mid-scalar BP byte so
        // execution reaches verifyRange64 and returns tecBAD_PROOF.
        testcase("convert-back BP-only tamper -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        std::uint64_t const bal = 100;
        std::uint64_t const m = 40;
        fundConvertMerge(
            env, alice, bob, mpt, bal, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spendingHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending));
        auto const issuerHex = strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(sk && pk && rho && rAmt);

        auto zk = makeConvertBackZk(
            bal, m, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        // Single BP layout: A,S,T1,T2 then tauX,mu,tHat,… Flip mid-byte of tauX.
        jtx::cmpt::mutateConvertBackBpByte(*zk, jtx::cmpt::bpTauXMidOffset());

        auto const pcB = pedersenCommit(bal, *rho);
        BEAST_EXPECT(pcB);
        auto const baseFee = env.current()->fees().base;
        env(convertBackJV(
                bob,
                mpt.issuanceID(),
                m,
                encryptHex(m, *pk, *rAmt),
                encryptHex(m, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk))),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
    }

    void
    testClawbackProofTamper()
    {
        testcase("clawback proof tamper -> tecBAD_PROOF");
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
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const spendingHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending));
        auto const inboxHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceInbox));
        auto const issuerHex = strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];
        auto const oaBefore = (*sleIss)[sfOutstandingAmount];

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
        auto proof = proveClawbackSigma(100, *sk, *pk, *issuerCt, makeSlice(ctxID));
        BEAST_EXPECT(proof);
        // Flip mid-byte of zsk (second 32-byte limb) — remains size-valid.
        jtx::cmpt::mutateClawbackByte(*proof, jtx::cmpt::SigmaOffsets::kClawbackZsk + 16);

        auto const baseFee = env.current()->fees().base;
        env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceInbox)) == inboxHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
    }

    void
    testClawbackWithAuditor()
    {
        // Distinct role keys: holder=1·G, issuer=3·G, auditor=2·G. EncZero
        // resets must use the matching pk per field; swapped holder/issuer
        // arguments in production would fail these exact equality checks.
        testcase("clawback with auditor resets EncZero fields");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        std::uint64_t const bal = 100;
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        mpt.create(
            {.ownerCount = 1,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKey3G,
             .auditorEncryptionKey = kKey2G});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const holderSk = parseScalarHex(kScalar1);
        auto const holderPk = parsePointHex(kKeyG);
        auto const issuerSk = parseScalarHex(kScalar3);
        auto const issuerPk = parsePointHex(kKey3G);
        auto const auditorPk = parsePointHex(kKey2G);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(holderSk && holderPk && issuerSk && issuerPk && auditorPk && r);

        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleIss);
        BEAST_EXPECT(strHex(sleIss->getFieldVL(sfIssuerEncryptionKey)) == kKey3G);
        BEAST_EXPECT(strHex(sleIss->getFieldVL(sfAuditorEncryptionKey)) == kKey2G);

        auto const holderCt = encryptHex(bal, *holderPk, *r);
        auto const issuerCt = encryptHex(bal, *issuerPk, *r);
        auto const auditorCt = encryptHex(bal, *auditorPk, *r);
        BEAST_EXPECT(!holderCt.empty() && !issuerCt.empty() && !auditorCt.empty());
        BEAST_EXPECT(holderCt != issuerCt && holderCt != auditorCt && issuerCt != auditorCt);

        auto const ctxID = jtx::cmpt::convertContextID(bob.id(), mpt.issuanceID(), env.seq(bob));
        auto const pok = proveRegisterPoK(*holderSk, *holderPk, makeSlice(ctxID));
        auto const baseFee = env.current()->fees().base;
        env(convertJV(
                bob,
                mpt.issuanceID(),
                bal,
                holderCt,
                issuerCt,
                kScalar2,
                std::string(kKeyG),
                strHex(makeSlice(*pok)),
                auditorCt),
            Fee(10 * baseFee));
        env.close();
        env(mergeJV(bob, mpt.issuanceID()), Fee(10 * baseFee));
        env.close();

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfAuditorEncryptedBalance));
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfHolderEncryptionKey)) == kKeyG);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const issuerBal =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
        BEAST_EXPECT(issuerBal);
        auto const specific = clawbackSpecific(bob.id());
        auto const clawCtx = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
            alice.id(),
            mpt.issuanceID(),
            env.seq(alice),
            makeSlice(specific));
        // Clawback sigma is under the issuer key against the issuer mirror.
        auto const proof =
            proveClawbackSigma(bal, *issuerSk, *issuerPk, *issuerBal, makeSlice(clawCtx));
        BEAST_EXPECT(proof);

        env(clawbackJV(alice, bob, mpt.issuanceID(), bal, strHex(makeSlice(*proof))),
            Fee(10 * baseFee));
        env.close();

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 0);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == 900);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version + 1);

        auto const expectHolder = encZero(bob.id(), alice.id(), mpt.issuanceID(), *holderPk);
        auto const expectIssuer = encZero(bob.id(), alice.id(), mpt.issuanceID(), *issuerPk);
        auto const expectAuditor = encZero(bob.id(), alice.id(), mpt.issuanceID(), *auditorPk);
        BEAST_EXPECT(expectHolder && expectIssuer && expectAuditor);
        auto const holderZeroHex = strHex(*expectHolder);
        auto const issuerZeroHex = strHex(*expectIssuer);
        auto const auditorZeroHex = strHex(*expectAuditor);
        // Same EncZero randomness, distinct pks → pairwise-distinct ciphertexts.
        BEAST_EXPECT(
            holderZeroHex != issuerZeroHex && holderZeroHex != auditorZeroHex &&
            issuerZeroHex != auditorZeroHex);

        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == holderZeroHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceInbox)) == holderZeroHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerZeroHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfAuditorEncryptedBalance)) == auditorZeroHex);
    }

    void
    testClawbackProofContextMismatch()
    {
        // Amount and holder bindings: valid ledger state, wrong proof context.
        testcase("clawback amount/holder context mismatch -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, carol}, .fund = false});
        fundConvertMerge(
            env,
            alice,
            bob,
            mpt,
            100,
            tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const coaBefore =
            (*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfConfidentialOutstandingAmount];
        auto const oaBefore = (*env.le(keylet::mptIssuance(mpt.issuanceID())))[sfOutstandingAmount];
        auto const issuerCt =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
        BEAST_EXPECT(issuerCt);
        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const baseFee = env.current()->fees().base;
        auto const fee = Fee(10 * baseFee);

        {
            // Prove amount 50 but submit amount 100 (same issuer CT).
            auto const specific = clawbackSpecific(bob.id());
            auto const ctxID = confidentialTxContextID(
                static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
                alice.id(),
                mpt.issuanceID(),
                env.seq(alice),
                makeSlice(specific));
            auto const proof = proveClawbackSigma(50, *sk, *pk, *issuerCt, makeSlice(ctxID));
            BEAST_EXPECT(proof);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
                fee,
                Ter(tecBAD_PROOF));
        }

        {
            // Prove under carol holder binding; submit clawback of bob.
            auto const specific = clawbackSpecific(carol.id());
            auto const ctxID = confidentialTxContextID(
                static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
                alice.id(),
                mpt.issuanceID(),
                env.seq(alice),
                makeSlice(specific));
            auto const proof = proveClawbackSigma(100, *sk, *pk, *issuerCt, makeSlice(ctxID));
            BEAST_EXPECT(proof);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
                fee,
                Ter(tecBAD_PROOF));
        }

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaBefore);
        BEAST_EXPECT(sleMpt->isFieldPresent(sfIssuerEncryptedBalance));
    }

    void
    testConvertBackAdversarialBindings()
    {
        // Sigma-only tamper; wrong blinding reconstruct; claimed balance/PC_b
        // mismatch with a valid BP on the claimed remainder; wrong version and
        // sequence contexts. All tecBAD_PROOF with unchanged ledger.
        testcase("convert-back adversarial bindings -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        std::uint64_t const bal = 100;
        std::uint64_t const m = 40;
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env, alice, bob, mpt, bal, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleMpt);
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const mptAmountBefore = (*sleMpt)[sfMPTAmount];
        auto const spendingHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending));
        auto const issuerHex = strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(sk && pk && rho && rAmt);
        auto const baseFee = env.current()->fees().base;
        auto const fee = Fee(10 * baseFee);

        auto submit = [&](std::uint64_t amount,
                          std::string const& holderCt,
                          std::string const& issuerCt,
                          std::string const& blinding,
                          std::string const& pc,
                          std::string const& zk) {
            env(convertBackJV(bob, mpt.issuanceID(), amount, holderCt, issuerCt, blinding, pc, zk),
                fee,
                Ter(tecBAD_PROOF));
        };

        {
            // Sigma-only tamper (BP untouched).
            auto zk = makeConvertBackZk(
                bal,
                m,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            BEAST_EXPECT(zk);
            jtx::cmpt::mutateConvertBackSigmaByte(*zk, jtx::cmpt::SigmaOffsets::kChallenge);
            auto const pcB = pedersenCommit(bal, *rho);
            BEAST_EXPECT(pcB);
            submit(
                m,
                encryptHex(m, *pk, *rAmt),
                encryptHex(m, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)));
        }
        {
            // Wrong blinding reconstruct: encrypt with r=1, claim r=2.
            auto const zk = makeConvertBackZk(
                bal,
                m,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            BEAST_EXPECT(zk);
            auto const pcB = pedersenCommit(bal, *rho);
            BEAST_EXPECT(pcB);
            submit(
                m,
                encryptHex(m, *pk, *rAmt),
                encryptHex(m, *pk, *rAmt),
                kScalar2,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)));
        }
        {
            // Claimed balance/PC_b does not match ledger spending; BP for the
            // claimed nonnegative remainder is still valid.
            std::uint64_t const claimed = 50;
            std::uint64_t const claimM = 10;
            auto const pcB = pedersenCommit(claimed, *rho);
            BEAST_EXPECT(pcB);
            auto const ctxID =
                jtx::cmpt::convertBackContextID(bob.id(), mpt.issuanceID(), env.seq(bob), version);
            auto const sigma =
                proveConvertBackSigma(claimed, *rho, *sk, *pk, *spending, *pcB, makeSlice(ctxID));
            auto const mG = generatorMultiply(Secp256k1Field::fromUint64(claimM));
            BEAST_EXPECT(sigma && mG);
            auto const pcRem = pointSubtract(*pcB, *mG);
            BEAST_EXPECT(pcRem);
            auto const bp = proveRange64(claimed - claimM, *rho, *pcRem);
            BEAST_EXPECT(bp);
            auto const annotated = jtx::cmpt::annotateConvertBackZk(
                *sigma, *bp, /*sigmaValidForBuiltStatement=*/true, /*bulletproofIsForeign=*/false);
            BEAST_EXPECT(annotated && annotated->sigmaValidForBuiltStatement);
            BEAST_EXPECT(verifyRange64(
                *pcRem,
                Slice(annotated->bytes.data() + kConvertBackSigmaSize, kSingleBulletproofSize)));
            submit(
                claimM,
                encryptHex(claimM, *pk, *rAmt),
                encryptHex(claimM, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(annotated->bytes)));
        }
        {
            // Wrong CBS version context.
            auto const zk = makeConvertBackZk(
                bal,
                m,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version + 1,
                env.seq(bob));
            BEAST_EXPECT(zk);
            auto const pcB = pedersenCommit(bal, *rho);
            BEAST_EXPECT(pcB);
            submit(
                m,
                encryptHex(m, *pk, *rAmt),
                encryptHex(m, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)));
        }
        {
            // Wrong sequence context.
            auto const zk = makeConvertBackZk(
                bal,
                m,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob) + 1);
            BEAST_EXPECT(zk);
            auto const pcB = pedersenCommit(bal, *rho);
            BEAST_EXPECT(pcB);
            submit(
                m,
                encryptHex(m, *pk, *rAmt),
                encryptHex(m, *pk, *rAmt),
                kScalar1,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)));
        }

        sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleMpt)[sfMPTAmount] == mptAmountBefore);
        BEAST_EXPECT((*sleMpt)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);
    }

    void
    testClawbackAdversarialBindings()
    {
        // Wrong sequence, wrong issuance context, and stale issuer-mirror proof
        // after a legitimate holder ConvertBack state change.
        testcase("clawback adversarial bindings -> tecBAD_PROOF");
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

        MPTTester mptOther(env, alice, {.holders = {bob}, .fund = false});
        mptOther.create(
            {.ownerCount = 2,
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback});
        mptOther.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const spendingHex = strHex(sleMpt->getFieldVL(sfConfidentialBalanceSpending));
        auto const issuerHex = strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance));
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const coaBefore = (*sleIss)[sfConfidentialOutstandingAmount];
        auto const oaBefore = (*sleIss)[sfOutstandingAmount];

        auto const issuerCt =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfIssuerEncryptedBalance)));
        BEAST_EXPECT(issuerCt);
        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        BEAST_EXPECT(sk && pk);
        auto const baseFee = env.current()->fees().base;
        auto const fee = Fee(10 * baseFee);

        {
            // Wrong sequence.
            auto const ctxID = jtx::cmpt::clawbackContextID(
                alice.id(), mpt.issuanceID(), env.seq(alice) + 1, bob.id());
            auto const proof = proveClawbackSigma(100, *sk, *pk, *issuerCt, makeSlice(ctxID));
            BEAST_EXPECT(proof);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
                fee,
                Ter(tecBAD_PROOF));
        }
        {
            // Wrong issuance context.
            auto const ctxID = jtx::cmpt::clawbackContextID(
                alice.id(), mptOther.issuanceID(), env.seq(alice), bob.id());
            auto const proof = proveClawbackSigma(100, *sk, *pk, *issuerCt, makeSlice(ctxID));
            BEAST_EXPECT(proof);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 100, strHex(makeSlice(*proof))),
                fee,
                Ter(tecBAD_PROOF));
        }
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaBefore);

        {
            // Stale issuer-mirror proof after a legitimate holder ConvertBack.
            // Prove clawback(60) against Enc(100), then ConvertBack 40 so the
            // mirror becomes Enc(60) while COA still admits amount 60.
            auto const staleCtx = jtx::cmpt::clawbackContextID(
                alice.id(), mpt.issuanceID(), env.seq(alice), bob.id());
            auto const staleProof =
                proveClawbackSigma(60, *sk, *pk, *issuerCt, makeSlice(staleCtx));
            BEAST_EXPECT(staleProof);

            auto const spending = parseElGamalCiphertext(
                makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
            auto const rho = parseScalarHex(kScalar2);
            auto const rAmt = parseScalarHex(kScalar1);
            BEAST_EXPECT(spending && rho && rAmt);
            auto const zk = makeConvertBackZk(
                100,
                40,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            auto const pcB = pedersenCommit(100, *rho);
            BEAST_EXPECT(zk && pcB);
            env(convertBackJV(
                    bob,
                    mpt.issuanceID(),
                    40,
                    encryptHex(40, *pk, *rAmt),
                    encryptHex(40, *pk, *rAmt),
                    kScalar1,
                    strHex(pcB->serialize()),
                    strHex(makeSlice(*zk))),
                Fee(10 * baseFee));
            env.close();

            // Issuer mirror changed; stale clawback proof must fail.
            env(clawbackJV(alice, bob, mpt.issuanceID(), 60, strHex(makeSlice(*staleProof))),
                fee,
                Ter(tecBAD_PROOF));

            sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT((*sleMpt)[sfMPTAmount] == 940);
            BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == 60);
            BEAST_EXPECT(strHex(sleMpt->getFieldVL(sfIssuerEncryptedBalance)) != issuerHex);
        }

        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaBefore);
    }

    void
    testConvertBackRejectGates()
    {
        testcase("convert-back rejection gates");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        constexpr std::size_t kZk = kConvertBackSigmaSize + kSingleBulletproofSize;
        std::uint64_t const bal = 100;
        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env,
            alice,
            bob,
            mpt,
            bal,
            tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rho = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && rho);

        auto sleMpt = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto const version = (*sleMpt)[sfConfidentialBalanceVersion];
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleMpt->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const zk = makeConvertBackZk(
            bal, 10, *rho, *sk, *pk, *spending, bob.id(), mpt.issuanceID(), version, env.seq(bob));
        BEAST_EXPECT(zk);
        auto const pcB = pedersenCommit(bal, *rho);
        auto const r = parseScalarHex(kScalar2);
        auto const holderCt = encryptHex(10, *pk, *r);
        auto const issuerCt = encryptHex(10, *pk, *r);
        auto const fee = Fee(10 * env.current()->fees().base);
        auto const pcHex = strHex(pcB->serialize());
        auto const zkHex = strHex(makeSlice(*zk));

        auto snap = [&]() {
            auto sle = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
            return std::make_tuple(
                (*sle)[sfMPTAmount],
                (*sle)[sfConfidentialBalanceVersion],
                sle->getFieldVL(sfConfidentialBalanceSpending),
                (*sleIss)[sfConfidentialOutstandingAmount]);
        };
        auto before = snap();

        // Preflight: amount > max, bad commitment/ciphertext/proof sizes.
        {
            auto j = convertBackJV(
                bob, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex);
            j[sfMPTAmount.jsonName] = std::to_string(kMaxMpTokenAmount + 1);
            env(j, fee, Ter(temBAD_AMOUNT));
        }
        {
            auto j = convertBackJV(
                bob, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex);
            j[sfBalanceCommitment.jsonName] = std::string(32, '0');
            env(j, fee, Ter(temMALFORMED));
        }
        {
            auto j = convertBackJV(
                bob, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex);
            j[sfHolderEncryptedAmount.jsonName] = std::string(10, '0');
            env(j, fee, Ter(temBAD_CIPHERTEXT));
        }
        {
            auto j = convertBackJV(
                bob, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex);
            j.removeMember(sfIssuerEncryptedAmount.jsonName);
            env(j, fee, Ter(temMALFORMED));
        }
        {
            auto j = convertBackJV(
                bob, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex);
            j[sfZKProof.jsonName] = std::string(kZk - 2, '0');
            env(j, fee, Ter(temMALFORMED));
        }
        BEAST_EXPECT(snap() == before);

        // Issuer as account → tecNO_PERMISSION
        env(convertBackJV(alice, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex),
            fee,
            Ter(tecNO_PERMISSION));

        // COA insufficient
        {
            auto const zkBig = makeConvertBackZk(
                bal,
                bal + 1,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            // May fail proof or funds; force amount > COA with dummy proof size ok
            auto j = convertBackJV(
                bob,
                mpt.issuanceID(),
                bal + 1,
                encryptHex(bal + 1, *pk, *r),
                encryptHex(bal + 1, *pk, *r),
                kScalar2,
                pcHex,
                zkBig ? strHex(makeSlice(*zkBig)) : std::string(2 * kZk, '0'));
            env(j, fee, Ter(tecINSUFFICIENT_FUNDS));
        }

        // Holder lock / issuance lock
        mpt.set({.account = alice, .holder = bob, .flags = tfMPTLock});
        env.close();
        {
            auto const zk2 = makeConvertBackZk(
                bal,
                10,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            BEAST_EXPECT(zk2);
            before = snap();
            env(convertBackJV(
                    bob,
                    mpt.issuanceID(),
                    10,
                    holderCt,
                    issuerCt,
                    kScalar2,
                    pcHex,
                    strHex(makeSlice(*zk2))),
                fee,
                Ter(tecLOCKED));
            BEAST_EXPECT(snap() == before);
        }
        mpt.set({.account = alice, .holder = bob, .flags = tfMPTUnlock});
        env.close();
        mpt.set({.account = alice, .flags = tfMPTLock});
        env.close();
        {
            auto const zk2 = makeConvertBackZk(
                bal,
                10,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            BEAST_EXPECT(zk2);
            before = snap();
            env(convertBackJV(
                    bob,
                    mpt.issuanceID(),
                    10,
                    holderCt,
                    issuerCt,
                    kScalar2,
                    pcHex,
                    strHex(makeSlice(*zk2))),
                fee,
                Ter(tecLOCKED));
            BEAST_EXPECT(snap() == before);
        }
        mpt.set({.account = alice, .flags = tfMPTUnlock});
        env.close();

        // Missing core confidential fields
        {
            auto const key = keylet::mptoken(mpt.issuanceID(), bob.id());
            auto const saved = std::make_shared<SLE>(*env.le(key), key.key);
            SF_VL const* fields[] = {
                &sfConfidentialBalanceSpending, &sfHolderEncryptionKey, &sfIssuerEncryptedBalance};
            for (auto const* f : fields)
            {
                before = snap();
                auto const ok =
                    env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                        auto replacement = std::make_shared<SLE>(*saved, saved->key());
                        replacement->makeFieldAbsent(*f);
                        view.rawReplace(replacement);
                        return true;
                    });
                BEAST_EXPECT(ok);
                auto const zk2 = makeConvertBackZk(
                    bal,
                    10,
                    *rho,
                    *sk,
                    *pk,
                    *spending,
                    bob.id(),
                    mpt.issuanceID(),
                    version,
                    env.seq(bob));
                BEAST_EXPECT(zk2);
                env(convertBackJV(
                        bob,
                        mpt.issuanceID(),
                        10,
                        holderCt,
                        issuerCt,
                        kScalar2,
                        pcHex,
                        strHex(makeSlice(*zk2))),
                    fee,
                    Ter(tecNO_PERMISSION));
                env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                    view.rawReplace(std::make_shared<SLE>(*saved, saved->key()));
                    return true;
                });
                BEAST_EXPECT(snap() == before);
            }
        }

        // Auditor amount-policy mismatch (no auditor key but amount present)
        {
            auto const auditorPk = parsePointHex(kKey2G);
            auto const auditorCt = encryptHex(10, *auditorPk, *r);
            auto const zk2 = makeConvertBackZk(
                bal,
                10,
                *rho,
                *sk,
                *pk,
                *spending,
                bob.id(),
                mpt.issuanceID(),
                version,
                env.seq(bob));
            BEAST_EXPECT(zk2);
            before = snap();
            env(convertBackJV(
                    bob,
                    mpt.issuanceID(),
                    10,
                    holderCt,
                    issuerCt,
                    kScalar2,
                    pcHex,
                    strHex(makeSlice(*zk2)),
                    auditorCt),
                fee,
                Ter(tecNO_PERMISSION));
            BEAST_EXPECT(snap() == before);
        }

        // Auditor key present, amount omitted → tecNO_PERMISSION (pairing).
        {
            Env envAud{*this, withConfidential()};
            Account const a{"alice"};
            Account const b{"bob"};
            envAud.fund(XRP(10000), a, b);
            envAud.close();
            MPTTester mAud(envAud, a, {.holders = {b}, .fund = false});
            mAud.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mAud.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G});
            mAud.authorize({.account = b});
            mAud.pay(a, b, 1000);
            auto const auditorPk = parsePointHex(kKey2G);
            auto const holderCtA = encryptHex(50, *pk, *r);
            auto const issuerCtA = encryptHex(50, *pk, *r);
            auto const auditorCtA = encryptHex(50, *auditorPk, *r);
            auto const ctxID =
                jtx::cmpt::convertContextID(b.id(), mAud.issuanceID(), envAud.seq(b));
            auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
            envAud(
                convertJV(
                    b,
                    mAud.issuanceID(),
                    50,
                    holderCtA,
                    issuerCtA,
                    kScalar2,
                    std::string(kKeyG),
                    strHex(makeSlice(*pok)),
                    auditorCtA),
                fee);
            envAud.close();
            envAud(mergeJV(b, mAud.issuanceID()), fee);
            envAud.close();
            auto sle = envAud.le(keylet::mptoken(mAud.issuanceID(), b.id()));
            auto const ver = (*sle)[sfConfidentialBalanceVersion];
            auto const spend =
                parseElGamalCiphertext(makeSlice(sle->getFieldVL(sfConfidentialBalanceSpending)));
            auto const zkA = makeConvertBackZk(
                50, 10, *rho, *sk, *pk, *spend, b.id(), mAud.issuanceID(), ver, envAud.seq(b));
            auto const pcA = pedersenCommit(50, *rho);
            BEAST_EXPECT(zkA && pcA && spend);
            // Omit auditor amount despite issuance auditor key.
            envAud(
                convertBackJV(
                    b,
                    mAud.issuanceID(),
                    10,
                    encryptHex(10, *pk, *r),
                    encryptHex(10, *pk, *r),
                    kScalar2,
                    strHex(pcA->serialize()),
                    strHex(makeSlice(*zkA))),
                fee,
                Ter(tecNO_PERMISSION));
        }

        // Missing issuance / !confidential already similar; cover missing token
        {
            Account const ghost{"ghost"};
            env.fund(XRP(10000), ghost);
            env.close();
            env(convertBackJV(
                    ghost, mpt.issuanceID(), 10, holderCt, issuerCt, kScalar2, pcHex, zkHex),
                fee,
                Ter(tecOBJECT_NOT_FOUND));
        }
    }

    void
    testClawbackRejectGates()
    {
        // Expands clawback failure coverage beyond the thin testClawbackFailures.
        testcase("clawback rejection gates");
        using namespace jtx;

        // ZKProof is hex-encoded; byte size kClawbackSigmaSize → 2× hex chars.
        constexpr std::size_t kProof = 2 * kClawbackSigmaSize;

        // Amendment disabled
        {
            Env env{*this, withoutConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();
            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create({.flags = tfMPTCanTransfer | tfMPTCanClawback});
            mpt.authorize({.account = bob});
            env(clawbackJV(alice, bob, mpt.issuanceID(), 1, std::string(kProof, '0')),
                Fee(10 * env.current()->fees().base),
                Ter(temDISABLED));
        }

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
        fundConvertMerge(
            env,
            alice,
            bob,
            mpt,
            100,
            tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanClawback);

        auto const fee = Fee(10 * env.current()->fees().base);
        auto snap = [&]() {
            auto sle = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
            return std::make_tuple(
                (*sleIss)[sfOutstandingAmount],
                (*sleIss)[sfConfidentialOutstandingAmount],
                (*sle)[sfConfidentialBalanceVersion],
                sle->getFieldVL(sfIssuerEncryptedBalance));
        };
        auto before = snap();

        // Missing holder account
        {
            Account const ghost{"ghost"};
            env(clawbackJV(alice, ghost, mpt.issuanceID(), 50, std::string(kProof, '0')),
                fee,
                Ter(tecNO_TARGET));
        }

        // Missing issuance
        env(clawbackJV(alice, bob, makeMptID(1, alice.id()), 50, std::string(kProof, '0')),
            fee,
            Ter(tecOBJECT_NOT_FOUND));

        // Missing token (charlie never authorized)
        env(clawbackJV(alice, charlie, mpt.issuanceID(), 50, std::string(kProof, '0')),
            fee,
            Ter(tecOBJECT_NOT_FOUND));

        // !CanClawback
        {
            MPTTester noCb(env, alice, {.holders = {charlie}, .fund = false});
            // Omit ownerCount: alice already owns the primary issuance in this Env.
            noCb.create({.flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            noCb.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            noCb.authorize({.account = charlie});
            noCb.pay(alice, charlie, 1000);
            auto const sk = parseScalarHex(kScalar1);
            auto const pk = parsePointHex(kKeyG);
            auto const r = parseScalarHex(kScalar2);
            auto const ct = encryptHex(50, *pk, *r);
            auto const ctxID =
                jtx::cmpt::convertContextID(charlie.id(), noCb.issuanceID(), env.seq(charlie));
            auto const pok = proveRegisterPoK(*sk, *pk, makeSlice(ctxID));
            env(convertJV(
                    charlie,
                    noCb.issuanceID(),
                    50,
                    ct,
                    ct,
                    kScalar2,
                    std::string(kKeyG),
                    strHex(makeSlice(*pok))),
                fee);
            env.close();
            env(mergeJV(charlie, noCb.issuanceID()), fee);
            env.close();
            env(clawbackJV(alice, charlie, noCb.issuanceID(), 10, std::string(kProof, '0')),
                fee,
                Ter(tecNO_PERMISSION));
        }

        // !confidential
        {
            MPTTester plain(env, alice, {.holders = {charlie}, .fund = false});
            plain.create({.flags = tfMPTCanTransfer | tfMPTCanClawback});
            plain.authorize({.account = charlie});
            plain.pay(alice, charlie, 50);
            env(clawbackJV(alice, charlie, plain.issuanceID(), 10, std::string(kProof, '0')),
                fee,
                Ter(tecNO_PERMISSION));
        }

        // Missing issuer key (OpenLedger strip). Rebuild without SoeDefault-at-default
        // fields so SLE construction does not throw on TransferFee=0.
        {
            before = snap();
            auto const issKey = keylet::mptIssuance(mpt.issuanceID());
            auto const savedSle = env.le(issKey);
            auto buildIssuanceSLE = [&](bool withIssuerKey) {
                STObject fields{sfLedgerEntry};
                for (auto const& field : *savedSle)
                {
                    if (field.getFName() == sfIssuerEncryptionKey && !withIssuerKey)
                        continue;
                    if (field.isDefault() &&
                        (field.getFName() == sfTransferFee || field.getFName() == sfAssetScale ||
                         field.getFName() == sfMutableFlags))
                        continue;
                    xrpl::detail::STVar var{field};
                    fields.set(std::move(var.get()));
                }
                return std::make_shared<SLE>(fields, issKey.key);
            };
            auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                view.rawReplace(buildIssuanceSLE(false));
                return true;
            });
            BEAST_EXPECT(ok);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(kProof, '0')),
                fee,
                Ter(tecNO_PERMISSION));
            env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                view.rawReplace(buildIssuanceSLE(true));
                return true;
            });
            BEAST_EXPECT(snap() == before);
        }

        // Missing each holder confidential field group
        {
            auto const key = keylet::mptoken(mpt.issuanceID(), bob.id());
            auto const saved = std::make_shared<SLE>(*env.le(key), key.key);
            SF_VL const* fields[] = {
                &sfIssuerEncryptedBalance,
                &sfHolderEncryptionKey,
                &sfConfidentialBalanceSpending,
                &sfConfidentialBalanceInbox};
            for (auto const* f : fields)
            {
                before = snap();
                env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                    auto replacement = std::make_shared<SLE>(*saved, saved->key());
                    replacement->makeFieldAbsent(*f);
                    view.rawReplace(replacement);
                    return true;
                });
                env(clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(kProof, '0')),
                    fee,
                    Ter(tecNO_PERMISSION));
                env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                    view.rawReplace(std::make_shared<SLE>(*saved, saved->key()));
                    return true;
                });
                BEAST_EXPECT(snap() == before);
            }
        }

        // COA insufficient (amount > COA)
        env(clawbackJV(alice, bob, mpt.issuanceID(), 101, std::string(kProof, '0')),
            fee,
            Ter(tecINSUFFICIENT_FUNDS));

        // OA insufficient while COA sufficient — inject OA below amount.
        {
            before = snap();
            auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                auto const sle = view.read(keylet::mptIssuance(mpt.issuanceID()));
                if (!sle)
                    return false;
                STObject fields{sfLedgerEntry};
                for (auto const& field : *sle)
                {
                    if (field.isDefault() &&
                        (field.getFName() == sfTransferFee || field.getFName() == sfAssetScale ||
                         field.getFName() == sfMutableFlags))
                        continue;
                    xrpl::detail::STVar var{field};
                    fields.set(std::move(var.get()));
                }
                auto replacement = std::make_shared<SLE>(fields, sle->key());
                (*replacement)[sfOutstandingAmount] = 10;
                // Keep COA at 100 so OA gate fires first when amount=50.
                view.rawReplace(replacement);
                return true;
            });
            BEAST_EXPECT(ok);
            env(clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(kProof, '0')),
                fee,
                Ter(tecINSUFFICIENT_FUNDS));
            env.close();  // drop open-ledger OA inject
        }

        // Malformed proof size / max amount
        env(clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(kProof - 2, '0')),
            fee,
            Ter(temMALFORMED));
        {
            auto j = clawbackJV(alice, bob, mpt.issuanceID(), 50, std::string(kProof, '0'));
            j[sfMPTAmount.jsonName] = std::to_string(kMaxMpTokenAmount + 1);
            env(j, fee, Ter(temBAD_AMOUNT));
        }
    }

    void
    run() override
    {
        testConvertBackHappy();
        testConvertBackDisabledAndZero();
        testConvertBackUnrepresentableSubtraction();
        testConvertBackFullAmountDifferentRandomness();
        testConvertBackAuditorMirrorAbsent();
        testConvertBackAuditorUnrepresentableSubtraction();
        testUnauthorizedConvertBack();
        testConvertBackBulletproofTamper();
        testConvertBackAdversarialBindings();
        testConvertBackRejectGates();
        testClawbackHappy();
        testClawbackFailures();
        testClawbackProofTamper();
        testClawbackWithAuditor();
        testClawbackProofContextMismatch();
        testClawbackAdversarialBindings();
        testClawbackRejectGates();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvertBackClawback, app, xrpl);

}  // namespace test
}  // namespace xrpl
