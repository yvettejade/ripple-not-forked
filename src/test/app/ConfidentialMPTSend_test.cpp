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

class ConfidentialMPTSend_test : public beast::unit_test::Suite
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
    static constexpr char const* kScalar3 =
        "0000000000000000000000000000000000000000000000000000000000000003";
    static constexpr char const* kScalar4 =
        "0000000000000000000000000000000000000000000000000000000000000004";
    static constexpr char const* kScalar5 =
        "0000000000000000000000000000000000000000000000000000000000000005";
    static constexpr char const* kScalar6 =
        "0000000000000000000000000000000000000000000000000000000000000006";
    static constexpr char const* kScalar7 =
        "0000000000000000000000000000000000000000000000000000000000000007";
    static constexpr std::size_t kSendZkProofSize = kSendSigmaSize + kAggregatedBulletproofSize;
    static constexpr std::size_t kConvertBackZkProofSize =
        kConvertBackSigmaSize + kSingleBulletproofSize;

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
        std::string const& zk,
        std::optional<std::string> auditorCt = std::nullopt)
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
        if (auditorCt)
            jv[sfAuditorEncryptedAmount] = *auditorCt;
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
        std::optional<std::string> auditorCt;
    };

    std::optional<SendWitness>
    buildSendWitness(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& destination,
        MPTID const& issuanceID,
        std::uint64_t balance,
        std::uint64_t amount,
        Secp256k1Scalar const* amountRandomness = nullptr,
        std::optional<Secp256k1Point> auditorPk = std::nullopt,
        Secp256k1Scalar const* balanceRandomness = nullptr,
        Secp256k1Scalar const* senderSkIn = nullptr,
        Secp256k1Point const* senderPkIn = nullptr,
        Secp256k1Point const* destPkIn = nullptr,
        Secp256k1Point const* issuerPkIn = nullptr)
    {
        auto sleSender = env.le(keylet::mptoken(issuanceID, sender.id()));
        if (!sleSender)
            return std::nullopt;
        auto const spending =
            parseElGamalCiphertext(makeSlice(sleSender->getFieldVL(sfConfidentialBalanceSpending)));
        if (!spending)
            return std::nullopt;
        auto const version = (*sleSender)[~sfConfidentialBalanceVersion].value_or(0);

        auto const skDefault = parseScalarHex(kScalar1);
        auto const pkDefault = parsePointHex(kKeyG);
        auto const rDefault = parseScalarHex(kScalar1);
        auto const rhoDefault = parseScalarHex(kScalar2);
        if (!skDefault || !pkDefault || !rDefault || !rhoDefault)
            return std::nullopt;
        Secp256k1Scalar const& sk = senderSkIn ? *senderSkIn : *skDefault;
        Secp256k1Point const& senderPk = senderPkIn ? *senderPkIn : *pkDefault;
        Secp256k1Point const& destPk = destPkIn ? *destPkIn : *pkDefault;
        Secp256k1Point const& issuerPk = issuerPkIn ? *issuerPkIn : *pkDefault;
        Secp256k1Scalar const& r = amountRandomness ? *amountRandomness : *rDefault;
        Secp256k1Scalar const& rho = balanceRandomness ? *balanceRandomness : *rhoDefault;

        // rem blind = ρ − r via field arithmetic. Callers that set amount
        // randomness equal to the default ρ (e.g. issuer-mirror = rConvert)
        // must pass a distinct balanceRandomness so remBlind is nonzero.
        auto const remBlindField =
            fieldSub(Secp256k1Field::fromScalar(rho), Secp256k1Field::fromScalar(r));
        auto const remBlind = remBlindField.toScalar();
        if (!remBlind)
            return std::nullopt;

        auto const senderCt = ElGamalCiphertext::encrypt(amount, senderPk, r);
        auto const destCt = ElGamalCiphertext::encrypt(amount, destPk, r);
        auto const issuerCt = ElGamalCiphertext::encrypt(amount, issuerPk, r);
        if (!senderCt || !destCt || !issuerCt)
            return std::nullopt;

        std::optional<ElGamalCiphertext> auditorAmountCt;
        if (auditorPk)
        {
            auditorAmountCt = ElGamalCiphertext::encrypt(amount, *auditorPk, r);
            if (!auditorAmountCt)
                return std::nullopt;
        }

        auto const pcM = pedersenCommit(amount, r);
        auto const pcB = pedersenCommit(balance, rho);
        if (!pcM || !pcB)
            return std::nullopt;

        // Compact sigma recipient order: sender, dest, issuer[, auditor].
        std::vector<Secp256k1Point> pks{senderPk, destPk, issuerPk};
        std::vector<ElGamalCiphertext> cts{*senderCt, *destCt, *issuerCt};
        if (auditorPk)
        {
            pks.push_back(*auditorPk);
            cts.push_back(*auditorAmountCt);
        }

        auto const specific = sendSpecific(destination.id(), version);
        auto const ctxID = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
            sender.id(),
            issuanceID,
            env.seq(sender),
            makeSlice(specific));

        auto const sigma = proveSendSigma(
            amount,
            r,
            balance,
            rho,
            sk,
            pks,
            senderPk,
            cts,
            *pcM,
            *pcB,
            *spending,
            makeSlice(ctxID));
        if (!sigma)
            return std::nullopt;

        auto const rem = balance - amount;
        auto const pcRem = pointSubtract(*pcB, *pcM);
        if (!pcRem)
            return std::nullopt;
        auto const bp = proveRange64Aggregated(amount, r, *pcM, rem, *remBlind, *pcRem);
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
        if (auditorAmountCt)
            w.auditorCt = strHex(auditorAmountCt->serialize());
        return w;
    }

    /** Test-only small-plaintext check: shared = sk·C1; C2−shared == amount·G.
        Amount 0 expects point-at-infinity (nullopt from pointSubtract).
        Fails when the ciphertext is under a different recipient key. */
    static bool
    expectDecryptsTo(ElGamalCiphertext const& ct, Secp256k1Scalar const& sk, std::uint64_t amount)
    {
        auto const shared = pointMultiply(ct.c1(), sk);
        if (!shared)
            return false;
        auto const diff = pointSubtract(ct.c2(), *shared);
        if (amount == 0)
            return !diff;
        auto const expected = generatorMultiply(Secp256k1Field::fromUint64(amount));
        return expected && diff && *diff == *expected;
    }

    static bool
    expectDecryptsField(Slice blob, Secp256k1Scalar const& sk, std::uint64_t amount)
    {
        auto const ct = parseElGamalCiphertext(blob);
        if (!ct)
            return false;
        return expectDecryptsTo(*ct, sk, amount);
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

    std::optional<std::array<std::uint8_t, kConvertBackZkProofSize>>
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
        std::array<std::uint8_t, kConvertBackZkProofSize> zk{};
        std::memcpy(zk.data(), sigma->data(), kConvertBackSigmaSize);
        std::memcpy(zk.data() + kConvertBackSigmaSize, bp->data(), kSingleBulletproofSize);
        return zk;
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
    testSigmaTamperedProof()
    {
        // Corrupt only the compact sigma prefix so verifySendSigma fails.
        testcase("sigma-only tamper -> tecBAD_PROOF");
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

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

        auto w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 25);
        BEAST_EXPECT(w);
        if (!w)
            return;
        // Flip one nibble in the sigma portion (hex offset < 2 * kSendSigmaSize).
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

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testBulletproofTamperedProof()
    {
        // Valid compact sigma prefix; corrupt only a mid-scalar BP byte so
        // execution reaches verifyRange64Aggregated and returns tecBAD_PROOF.
        testcase("send BP-only tamper -> tecBAD_PROOF");
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

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingHex = strHex(sleBob->getFieldVL(sfConfidentialBalanceSpending));
        auto const inboxHex = strHex(sleCharlie->getFieldVL(sfConfidentialBalanceInbox));

        auto w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 25);
        BEAST_EXPECT(w);
        if (!w)
            return;

        // Aggregated BP layout (same prefix as single): A,S,T1,T2 then
        // tauX,mu,tHat,… Flip mid-byte of tauX inside the BP portion.
        constexpr std::size_t kBpTauXMid =
            4 * Secp256k1Point::kSerializedSize + Secp256k1Scalar::kSerializedSize / 2;
        auto const zkBytesOpt = strUnHex(w->zkHex);
        BEAST_EXPECT(zkBytesOpt && zkBytesOpt->size() == kSendZkProofSize);
        if (!zkBytesOpt || zkBytesOpt->size() != kSendZkProofSize)
            return;
        std::vector<std::uint8_t> zkBytes(zkBytesOpt->begin(), zkBytesOpt->end());
        zkBytes[kSendSigmaSize + kBpTauXMid] ^= 0x01;
        w->zkHex = strHex(makeSlice(zkBytes));

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

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleBob->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)) == inboxHex);
    }

    void
    testDestinationTagNeeded()
    {
        testcase("RequireDestTag without DestinationTag -> tecDST_TAG_NEEDED");
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

        env(fset(charlie, asfRequireDest));
        env.close();

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

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
            fee,
            Ter(tecDST_TAG_NEEDED));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testDestinationTagSuccess()
    {
        testcase("RequireDestTag with DestinationTag succeeds");
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

        env(fset(charlie, asfRequireDest));
        env.close();

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

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
            fee,
            Dtag(7));
        env.close();

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) != spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) != inboxBefore);
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

    // TransferFee mutex: ConfidentialMPTSend::preclaim rejects nonzero
    // TransferFee, but create+set cannot produce confidential + nonzero fee
    // together. Coverage lives in ConfidentialMPTIssuance_test::testTransferFeeMutex;
    // no Send jtx forces that unreachable ledger state.

    void
    testSendLocked()
    {
        testcase("send while issuance locked");
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
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, 100);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
        BEAST_EXPECT(w);
        if (!w)
            return;

        mpt.set({.flags = tfMPTLock});
        env.close();

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
            Ter(tecLOCKED));
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

    void
    testUnrepresentableSenderSubtraction()
    {
        testcase("send rejects amount CT equal to stored sender balances");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const bal = 100;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, bal);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBlob = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerBlob = sleBob->getFieldVL(sfIssuerEncryptedBalance);
        auto const spendingHex = strHex(spendingBlob);
        auto const issuerHex = strHex(issuerBlob);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rConvert = parseScalarHex(kScalar2);
        auto const rZero = encZeroRandomness(bob.id(), alice.id(), mpt.issuanceID());
        BEAST_EXPECT(sk && pk && rConvert && rZero);

        // After convert+merge (#16 first-write): inbox = Enc(bal, rConvert),
        // spending was EncZero → merged spending = Enc(bal, rZero + rConvert).
        auto const spendR = fieldToScalar(
            fieldAdd(Secp256k1Field::fromScalar(*rZero), Secp256k1Field::fromScalar(*rConvert)));
        BEAST_EXPECT(spendR);
        BEAST_EXPECT(encryptHex(bal, *pk, *spendR) == spendingHex);

        auto const wSpend =
            buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, bal, &*spendR);
        BEAST_EXPECT(wSpend);
        if (!wSpend)
            return;

        auto const baseFee = env.current()->fees().base;
        // Valid proof, but transfer CTs equal stored spending → infinity under ⊖.
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                wSpend->senderCt,
                wSpend->destCt,
                wSpend->issuerCt,
                wSpend->pcBHex,
                wSpend->pcMHex,
                wSpend->zkHex),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleBob->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(strHex(sleBob->getFieldVL(sfIssuerEncryptedBalance)) == issuerHex);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);

        // Issuer-mirror equality: first-write issuer CT = Enc(bal, rConvert).
        // Use distinct balance blinding so remBlind = ρ − rConvert ≠ 0.
        auto const issuerR = rConvert;
        auto const rhoIssuer = parseScalarHex(kScalar1);
        BEAST_EXPECT(rhoIssuer);
        BEAST_EXPECT(encryptHex(bal, *pk, *issuerR) == issuerHex);

        auto const wIssuer = buildSendWitness(
            env, bob, charlie, mpt.issuanceID(), bal, bal, &*issuerR, std::nullopt, &*rhoIssuer);
        BEAST_EXPECT(wIssuer);
        if (!wIssuer)
            return;
        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                wIssuer->senderCt,
                wIssuer->destCt,
                wIssuer->issuerCt,
                wIssuer->pcBHex,
                wIssuer->pcMHex,
                wIssuer->zkHex),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(strHex(sleBob->getFieldVL(sfConfidentialBalanceSpending)) == spendingHex);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testFullBalanceDifferentRandomness()
    {
        testcase("send full balance with distinct transfer CT randomness");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const bal = 100;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
        fundConvertMerge(env, alice, bob, mpt, bal);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

        auto const pk = parsePointHex(kKeyG);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(pk && rAmt);
        // Distinct from convert/merge randomness so Enc(bal, rAmt) ≠ stored CTs.
        BEAST_EXPECT(encryptHex(bal, *pk, *rAmt) != strHex(spendingBefore));

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, bal, &*rAmt);
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
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) != spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) != inboxBefore);
    }

    void
    testMissingAuditorMirror()
    {
        testcase("send rejects missing sender auditor mirror");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const bal = 50;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .auditorEncryptionKey = kKey2G});

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const auditorPk = parsePointHex(kKey2G);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && auditorPk && r);

        auto fundWithAuditor = [&](Account const& holder, std::uint64_t amount) {
            mpt.authorize({.account = holder});
            if (amount > 0)
                mpt.pay(alice, holder, amount > 1000 ? amount : 1000);
            auto const holderCt = encryptHex(amount, *pk, *r);
            auto const issuerCt = encryptHex(amount, *pk, *r);
            auto const auditorCt = encryptHex(amount, *auditorPk, *r);
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
                    strHex(makeSlice(*pok)),
                    auditorCt),
                Fee(10 * baseFee));
            env.close();
            env(mergeJV(holder, mpt.issuanceID()), Fee(10 * baseFee));
            env.close();
        };

        fundWithAuditor(bob, bal);
        fundWithAuditor(charlie, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleBob && sleBob->isFieldPresent(sfAuditorEncryptedBalance));
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);

        // Drop sender auditor mirror while issuance still requires auditor amounts.
        // Do not env.close() before Send — close rebuilds the open ledger.
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
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleBob && !sleBob->isFieldPresent(sfAuditorEncryptedBalance));

        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rAmt);
        auto const w =
            buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, 10, &*rAmt, *auditorPk);
        BEAST_EXPECT(w && w->auditorCt);
        if (!w || !w->auditorCt)
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
                w->zkHex,
                *w->auditorCt),
            Fee(10 * baseFee),
            Ter(tecNO_PERMISSION));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(!sleBob->isFieldPresent(sfAuditorEncryptedBalance));
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
    }

    void
    testAuditorUnrepresentableSubtraction()
    {
        testcase("send rejects amount CT equal to auditor mirror");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const bal = 50;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .auditorEncryptionKey = kKey2G});

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const auditorPk = parsePointHex(kKey2G);
        auto const r = parseScalarHex(kScalar2);
        BEAST_EXPECT(sk && pk && auditorPk && r);

        auto fundWithAuditor = [&](Account const& holder, std::uint64_t amount) {
            mpt.authorize({.account = holder});
            if (amount > 0)
                mpt.pay(alice, holder, amount > 1000 ? amount : 1000);
            auto const holderCt = encryptHex(amount, *pk, *r);
            auto const issuerCt = encryptHex(amount, *pk, *r);
            auto const auditorCt = encryptHex(amount, *auditorPk, *r);
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
                    strHex(makeSlice(*pok)),
                    auditorCt),
                Fee(10 * baseFee));
            env.close();
            env(mergeJV(holder, mpt.issuanceID()), Fee(10 * baseFee));
            env.close();
        };

        fundWithAuditor(bob, bal);
        fundWithAuditor(charlie, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT(sleBob && sleBob->isFieldPresent(sfAuditorEncryptedBalance));
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);

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

        auto const w =
            buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, bal, &*rAmt, *auditorPk);
        BEAST_EXPECT(w && w->auditorCt);
        if (!w || !w->auditorCt)
            return;
        BEAST_EXPECT(*w->auditorCt == amtAuditorHex);

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
                w->zkHex,
                *w->auditorCt),
            Fee(10 * baseFee),
            Ter(tecBAD_PROOF));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
    }

    void
    testDistinctKeysLifecycle()
    {
        testcase("lifecycle with distinct holder/issuer/auditor keys");
        using namespace jtx;

        // Distinct secp256k1 key pairs — no shared holder/issuer secrets.
        auto const senderSk = parseScalarHex(kScalar1);
        auto const destSk = parseScalarHex(kScalar3);
        auto const issuerSk = parseScalarHex(kScalar4);
        auto const auditorSk = parseScalarHex(kScalar2);
        BEAST_EXPECT(senderSk && destSk && issuerSk && auditorSk);
        if (!senderSk || !destSk || !issuerSk || !auditorSk)
            return;

        auto const senderPk = generatorMultiply(*senderSk);
        auto const destPk = generatorMultiply(*destSk);
        auto const issuerPk = generatorMultiply(*issuerSk);
        auto const auditorPk = generatorMultiply(*auditorSk);
        BEAST_EXPECT(senderPk && destPk && issuerPk && auditorPk);
        if (!senderPk || !destPk || !issuerPk || !auditorPk)
            return;

        auto const senderKeyHex = strHex(senderPk->serialize());
        auto const destKeyHex = strHex(destPk->serialize());
        auto const issuerKeyHex = strHex(issuerPk->serialize());
        auto const auditorKeyHex = strHex(auditorPk->serialize());
        BEAST_EXPECT(senderKeyHex != destKeyHex);
        BEAST_EXPECT(senderKeyHex != issuerKeyHex);
        BEAST_EXPECT(senderKeyHex != auditorKeyHex);
        BEAST_EXPECT(destKeyHex != issuerKeyHex);
        BEAST_EXPECT(destKeyHex != auditorKeyHex);
        BEAST_EXPECT(issuerKeyHex != auditorKeyHex);

        // Same plaintext/randomness under distinct keys must not collide.
        auto const rProbe = parseScalarHex(kScalar5);
        BEAST_EXPECT(rProbe);
        auto const probeSender = encryptHex(7, *senderPk, *rProbe);
        auto const probeDest = encryptHex(7, *destPk, *rProbe);
        auto const probeIssuer = encryptHex(7, *issuerPk, *rProbe);
        auto const probeAuditor = encryptHex(7, *auditorPk, *rProbe);
        BEAST_EXPECT(!probeSender.empty());
        BEAST_EXPECT(probeSender != probeDest);
        BEAST_EXPECT(probeSender != probeIssuer);
        BEAST_EXPECT(probeSender != probeAuditor);
        BEAST_EXPECT(probeDest != probeIssuer);
        BEAST_EXPECT(probeDest != probeAuditor);
        BEAST_EXPECT(probeIssuer != probeAuditor);
        {
            auto const ct = ElGamalCiphertext::encrypt(7, *senderPk, *rProbe);
            BEAST_EXPECT(ct);
            BEAST_EXPECT(expectDecryptsTo(*ct, *senderSk, 7));
            BEAST_EXPECT(!expectDecryptsTo(*ct, *destSk, 7));
            BEAST_EXPECT(!expectDecryptsTo(*ct, *issuerSk, 7));
            BEAST_EXPECT(!expectDecryptsTo(*ct, *auditorSk, 7));
        }

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const convertAmt = 100;
        std::uint64_t const sendAmt = 40;
        std::uint64_t const publicFund = 1000;

        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = issuerKeyHex,
             .auditorEncryptionKey = auditorKeyHex});

        auto const baseFee = env.current()->fees().base;
        auto const fee = Fee(10 * baseFee);

        auto convertInit = [&](Account const& holder,
                               Secp256k1Scalar const& sk,
                               Secp256k1Point const& pk,
                               std::string const& keyHex,
                               std::uint64_t amount,
                               char const* rHex) {
            mpt.authorize({.account = holder});
            if (amount > 0)
                mpt.pay(alice, holder, publicFund);
            auto const r = parseScalarHex(rHex);
            BEAST_EXPECT(r);
            auto const holderCt = encryptHex(amount, pk, *r);
            auto const issuerCt = encryptHex(amount, *issuerPk, *r);
            auto const auditorCt = encryptHex(amount, *auditorPk, *r);
            BEAST_EXPECT(holderCt != issuerCt);
            BEAST_EXPECT(holderCt != auditorCt);
            BEAST_EXPECT(issuerCt != auditorCt);
            auto const ctxID = confidentialTxContextID(
                static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
                holder.id(),
                mpt.issuanceID(),
                env.seq(holder));
            auto const pok = proveRegisterPoK(sk, pk, makeSlice(ctxID));
            BEAST_EXPECT(pok);
            env(convertJV(
                    holder,
                    mpt.issuanceID(),
                    amount,
                    holderCt,
                    issuerCt,
                    rHex,
                    keyHex,
                    strHex(makeSlice(*pok)),
                    auditorCt),
                fee);
            env.close();
        };

        // 1) Issuance already set with issuer + auditor keys.
        // 2) Convert init for sender and destination under distinct holder keys.
        convertInit(bob, *senderSk, *senderPk, senderKeyHex, convertAmt, kScalar5);
        convertInit(charlie, *destSk, *destPk, destKeyHex, 0, kScalar6);

        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleIss);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == convertAmt);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == publicFund);
        auto const oaAfterIssuance = (*sleIss)[sfOutstandingAmount];
        auto const coaAfterIssuance = (*sleIss)[sfConfidentialOutstandingAmount];

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        BEAST_EXPECT(strHex(sleBob->getFieldVL(sfHolderEncryptionKey)) == senderKeyHex);
        BEAST_EXPECT(strHex(sleCharlie->getFieldVL(sfHolderEncryptionKey)) == destKeyHex);

        // Decrypt convert inboxes under intended keys (pre-merge).
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceInbox)), *senderSk, convertAmt));
        BEAST_EXPECT(!expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceInbox)), *destSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *destSk, 0));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, 0));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, 0));

        // 3) Merge sender.
        env(mergeJV(bob, mpt.issuanceID()), fee);
        env.close();
        // Destination needs confidential init merge of Enc(0) before receive.
        env(mergeJV(charlie, mpt.issuanceID()), fee);
        env.close();

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *senderSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, convertAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceSpending)), *destSk, 0));

        // 4) Send bob→charlie with four-key compact sigma + aggregated range proof.
        auto const rSend = parseScalarHex(kScalar7);
        auto const rhoSend = parseScalarHex(kScalar5);
        BEAST_EXPECT(rSend && rhoSend);
        auto const w = buildSendWitness(
            env,
            bob,
            charlie,
            mpt.issuanceID(),
            convertAmt,
            sendAmt,
            &*rSend,
            *auditorPk,
            &*rhoSend,
            &*senderSk,
            &*senderPk,
            &*destPk,
            &*issuerPk);
        BEAST_EXPECT(w && w->auditorCt);
        if (!w || !w->auditorCt)
            return;
        BEAST_EXPECT(w->senderCt != w->destCt);
        BEAST_EXPECT(w->senderCt != w->issuerCt);
        BEAST_EXPECT(w->senderCt != *w->auditorCt);
        BEAST_EXPECT(w->destCt != w->issuerCt);
        BEAST_EXPECT(w->destCt != *w->auditorCt);
        BEAST_EXPECT(w->issuerCt != *w->auditorCt);

        env(sendJV(
                bob,
                charlie,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex,
                *w->auditorCt),
            fee);
        env.close();

        // 5) Decrypt/verify after send.
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleBob && sleCharlie && sleIss);
        std::uint64_t const bobRem = convertAmt - sendAmt;
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *senderSk, bobRem));
        BEAST_EXPECT(!expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *destSk, bobRem));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, bobRem));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, bobRem));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *destSk, sendAmt));
        BEAST_EXPECT(!expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *senderSk, sendAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, sendAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, sendAmt));
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaAfterIssuance);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coaAfterIssuance);

        // 6) Merge destination.
        env(mergeJV(charlie, mpt.issuanceID()), fee);
        env.close();
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleCharlie);
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceSpending)), *destSk, sendAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, sendAmt));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, sendAmt));

        // 7) ConvertBack from destination with distinct issuer/auditor ciphertexts.
        auto const spending = parseElGamalCiphertext(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceSpending)));
        BEAST_EXPECT(spending);
        auto const version = (*sleCharlie)[sfConfidentialBalanceVersion];
        auto const rBack = parseScalarHex(kScalar6);
        auto const rhoBack = parseScalarHex(kScalar7);
        BEAST_EXPECT(rBack && rhoBack);
        auto const zk = makeConvertBackZk(
            sendAmt,
            sendAmt,
            *rhoBack,
            *destSk,
            *destPk,
            *spending,
            charlie.id(),
            mpt.issuanceID(),
            version,
            env.seq(charlie));
        BEAST_EXPECT(zk);
        if (!zk)
            return;
        auto const pcB = pedersenCommit(sendAmt, *rhoBack);
        BEAST_EXPECT(pcB);
        auto const holderBack = encryptHex(sendAmt, *destPk, *rBack);
        auto const issuerBack = encryptHex(sendAmt, *issuerPk, *rBack);
        auto const auditorBack = encryptHex(sendAmt, *auditorPk, *rBack);
        BEAST_EXPECT(holderBack != issuerBack);
        BEAST_EXPECT(holderBack != auditorBack);
        BEAST_EXPECT(issuerBack != auditorBack);

        auto const charliePublicBefore = (*sleCharlie)[sfMPTAmount];
        env(convertBackJV(
                charlie,
                mpt.issuanceID(),
                sendAmt,
                holderBack,
                issuerBack,
                kScalar6,
                strHex(pcB->serialize()),
                strHex(makeSlice(*zk)),
                auditorBack),
            fee);
        env.close();

        // 8) Final decrypt + public/OA/COA accounting.
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(sleCharlie && sleBob && sleIss);
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceSpending)), *destSk, 0));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *issuerSk, 0));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfAuditorEncryptedBalance)), *auditorSk, 0));
        BEAST_EXPECT(!expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceSpending)), *senderSk, 0));
        // Bob still holds the unsent confidential remainder.
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *senderSk, bobRem));
        BEAST_EXPECT((*sleCharlie)[sfMPTAmount] == charliePublicBefore + sendAmt);
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oaAfterIssuance);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == convertAmt - sendAmt);
        BEAST_EXPECT((*sleBob)[sfMPTAmount] == publicFund - convertAmt);
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
        testSigmaTamperedProof();
        testBulletproofTamperedProof();
        testDestinationTagNeeded();
        testDestinationTagSuccess();
        testFeeMultiplier();
        testDepositAuth();
        testSendLocked();
        testRequireAuthSuccess();
        testRequireAuthSenderRevoked();
        testRequireAuthDestUnauthorized();
        testUnrepresentableSenderSubtraction();
        testFullBalanceDifferentRandomness();
        testMissingAuditorMirror();
        testAuditorUnrepresentableSubtraction();
        testDistinctKeysLifecycle();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSend, app, xrpl);

}  // namespace test
}  // namespace xrpl
