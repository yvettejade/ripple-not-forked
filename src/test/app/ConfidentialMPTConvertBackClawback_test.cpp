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
#include <xrpl/ledger/OpenView.h>
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
#include <memory>
#include <optional>
#include <string>
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
        auto const specific = convertBackSpecific(account, version);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
            account,
            issuanceID,
            seq,
            makeSlice(specific));
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
        std::array<std::uint8_t, kConvertBackSigmaSize + kSingleBulletproofSize> zk{};
        std::memcpy(zk.data(), sigma->data(), kConvertBackSigmaSize);
        std::memcpy(zk.data() + kConvertBackSigmaSize, bp->data(), kSingleBulletproofSize);
        return zk;
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

        // After convert+merge: spending = Enc(bal, 2·rZero + rConvert).
        auto const spendR = fieldToScalar(fieldAdd(
            fieldAdd(Secp256k1Field::fromScalar(*rZero), Secp256k1Field::fromScalar(*rZero)),
            Secp256k1Field::fromScalar(*rConvert)));
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

        // Issuer-mirror equality: amount CT = issuer balance (r = rZero + rConvert).
        auto const issuerR = fieldToScalar(
            fieldAdd(Secp256k1Field::fromScalar(*rZero), Secp256k1Field::fromScalar(*rConvert)));
        BEAST_EXPECT(issuerR);
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
    run() override
    {
        testConvertBackHappy();
        testConvertBackDisabledAndZero();
        testConvertBackUnrepresentableSubtraction();
        testConvertBackFullAmountDifferentRandomness();
        testConvertBackAuditorMirrorAbsent();
        testConvertBackAuditorUnrepresentableSubtraction();
        testClawbackHappy();
        testClawbackFailures();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvertBackClawback, app, xrpl);

}  // namespace test
}  // namespace xrpl
