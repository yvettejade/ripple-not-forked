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
#include <test/jtx/credentials.h>
#include <test/jtx/deposit.h>
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
        return jtx::cmpt::encodeSendTxSpecific(destination, version);
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
        auto const ctxID =
            jtx::cmpt::convertContextID(holder.id(), mpt.issuanceID(), env.seq(holder));
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
        Secp256k1Point const* issuerPkIn = nullptr,
        std::optional<AccountID> contextDestination = std::nullopt,
        std::optional<std::uint32_t> contextVersion = std::nullopt,
        std::optional<std::uint32_t> contextSequence = std::nullopt,
        bool permuteDestIssuerRolesInSigma = false,
        Secp256k1Scalar const* destAmountRandomness = nullptr,
        std::optional<MPTID> contextIssuanceID = std::nullopt)
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
        Secp256k1Scalar const& destR = destAmountRandomness ? *destAmountRandomness : r;
        auto const destCt = ElGamalCiphertext::encrypt(amount, destPk, destR);
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
        // Optional adversarial permutation swaps dest/issuer roles inside the
        // sigma statement while transaction fields stay canonical.
        std::vector<Secp256k1Point> pks;
        std::vector<ElGamalCiphertext> cts;
        if (permuteDestIssuerRolesInSigma)
        {
            pks = {senderPk, issuerPk, destPk};
            cts = {*senderCt, *issuerCt, *destCt};
        }
        else
        {
            pks = {senderPk, destPk, issuerPk};
            cts = {*senderCt, *destCt, *issuerCt};
        }
        if (auditorPk)
        {
            pks.push_back(*auditorPk);
            cts.push_back(*auditorAmountCt);
        }

        auto const ctxDest = contextDestination.value_or(destination.id());
        auto const ctxVersion = contextVersion.value_or(version);
        auto const ctxSeq = contextSequence.value_or(env.seq(sender));
        auto const ctxIssuance = contextIssuanceID.value_or(issuanceID);
        auto const ctxID =
            jtx::cmpt::sendContextID(sender.id(), ctxIssuance, ctxSeq, ctxDest, ctxVersion);

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

        auto const zk = jtx::cmpt::spliceSendZk(*sigma, *bp);

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

    /** Send debit: balance ⊖ amount CT (no EncZero remix). */
    static std::optional<Blob>
    expectSendDebit(Blob const& before, std::string const& amountCtHex)
    {
        auto const amountBytes = strUnHex(amountCtHex);
        if (!amountBytes)
            return std::nullopt;
        return homomorphicSubCiphertexts(makeSlice(before), makeSlice(*amountBytes));
    }

    /** Send credit: before ⊕ (amount CT ⊕ Enc(0; e)) under rolePk. */
    static std::optional<Blob>
    expectSendCredit(
        Blob const& before,
        std::string const& amountCtHex,
        Secp256k1Point const& rolePk,
        Secp256k1Scalar const& e)
    {
        auto const amountBytes = strUnHex(amountCtHex);
        if (!amountBytes)
            return std::nullopt;
        auto const amountCt = parseElGamalCiphertext(makeSlice(*amountBytes));
        auto const beforeCt = parseElGamalCiphertext(makeSlice(before));
        auto const encZeroE = ElGamalCiphertext::encrypt(0, rolePk, e);
        if (!amountCt || !beforeCt || !encZeroE)
            return std::nullopt;
        auto const credited = amountCt->add(*encZeroE);
        if (!credited)
            return std::nullopt;
        auto const expected = beforeCt->add(*credited);
        if (!expected)
            return std::nullopt;
        auto const ser = expected->serialize();
        return Blob(ser.begin(), ser.end());
    }

    static std::optional<Secp256k1Scalar>
    sigmaChallengeFromZkHex(std::string const& zkHex)
    {
        if (zkHex.size() < 64)
            return std::nullopt;
        auto const eHex = zkHex.substr(0, 64);
        return parseScalarHex(eHex.c_str());
    }

    static std::array<std::uint8_t, 24>
    convertBackSpecific(AccountID const& account, std::uint32_t version)
    {
        return jtx::cmpt::encodeConvertBackTxSpecific(account, version);
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
        auto const zk = jtx::cmpt::spliceConvertBackZk(*sigma, *bp);
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

    /** Valid compact Send sigma for amount > spending balance, with an
        aggregated Bulletproof that is structurally valid for different
        nonnegative (amount, rem) commitments. Sigma verifies; range check
        must reject. If verifyRange64Aggregated were removed, this would
        apply successfully (no earlier malformation). */
    std::optional<SendWitness>
    buildOverdraftSendWitness(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& destination,
        MPTID const& issuanceID,
        std::uint64_t realBalance,
        std::uint64_t claimAmount)
    {
        BEAST_EXPECT(claimAmount > realBalance);
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

        auto const senderCt = ElGamalCiphertext::encrypt(claimAmount, *pk, *r);
        auto const destCt = ElGamalCiphertext::encrypt(claimAmount, *pk, *r);
        auto const issuerCt = ElGamalCiphertext::encrypt(claimAmount, *pk, *r);
        if (!senderCt || !destCt || !issuerCt)
            return std::nullopt;

        auto const pcM = pedersenCommit(claimAmount, *r);
        auto const pcB = pedersenCommit(realBalance, *rho);
        if (!pcM || !pcB)
            return std::nullopt;

        std::vector<Secp256k1Point> pks{*pk, *pk, *pk};
        std::vector<ElGamalCiphertext> cts{*senderCt, *destCt, *issuerCt};

        auto const ctxID = jtx::cmpt::sendContextID(
            sender.id(), issuanceID, env.seq(sender), destination.id(), version);

        // Honest sigma for the overdraft claim (range is BP's job).
        auto const sigma = proveSendSigma(
            claimAmount,
            *r,
            realBalance,
            *rho,
            *sk,
            pks,
            *pk,
            cts,
            *pcM,
            *pcB,
            *spending,
            makeSlice(ctxID));
        if (!sigma)
            return std::nullopt;

        // Foreign nonnegative openings: BP verifies alone, but not against
        // transaction pcM / (pcB − pcM). Annotated as bulletproofIsForeign.
        auto const foreignRField =
            fieldAdd(Secp256k1Field::fromScalar(*r), Secp256k1Field::fromScalar(*rho));
        auto const foreignR = foreignRField.toScalar();
        auto const foreignRemBlindField =
            fieldAdd(Secp256k1Field::fromScalar(*rho), Secp256k1Field::fromScalar(*rho));
        auto const foreignRemBlind = foreignRemBlindField.toScalar();
        if (!foreignR || !foreignRemBlind)
            return std::nullopt;
        std::uint64_t const foreignRem = 5;
        auto const foreignBp = jtx::cmpt::makeForeignAggregatedBulletproof(
            claimAmount, *foreignR, foreignRem, *foreignRemBlind);
        if (!foreignBp)
            return std::nullopt;
        BEAST_EXPECT(foreignBp->bulletproofIsForeign);
        auto const& bp = foreignBp->proof;

        auto const zk = jtx::cmpt::spliceSendZk(*sigma, bp);

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
        auto zkBytesOpt = strUnHex(w->zkHex);
        BEAST_EXPECT(zkBytesOpt && zkBytesOpt->size() == kSendZkProofSize);
        if (!zkBytesOpt || zkBytesOpt->size() != kSendZkProofSize)
            return;
        std::array<std::uint8_t, kSendZkProofSize> zkBytes{};
        std::memcpy(zkBytes.data(), zkBytesOpt->data(), kSendZkProofSize);
        jtx::cmpt::mutateSendBpByte(zkBytes, jtx::cmpt::bpTauXMidOffset());
        w->zkHex = jtx::cmpt::hexOf(zkBytes);

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
        std::uint64_t const bal = 100;
        std::uint64_t const amount = 10;
        fundConvertMerge(env, alice, bob, mpt, bal);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const senderIssuerBefore = sleBob->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const destIssuerBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const oa = (*sleIss)[sfOutstandingAmount];
        auto const coa = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const e = sigmaChallengeFromZkHex(w->zkHex);
        BEAST_EXPECT(sk && pk && e);
        auto const expectedSpending = expectSendDebit(spendingBefore, w->senderCt);
        auto const expectedSenderIssuer = expectSendDebit(senderIssuerBefore, w->issuerCt);
        auto const expectedInbox = expectSendCredit(inboxBefore, w->destCt, *pk, *e);
        auto const expectedDestIssuer = expectSendCredit(destIssuerBefore, w->issuerCt, *pk, *e);
        BEAST_EXPECT(
            expectedSpending && expectedSenderIssuer && expectedInbox && expectedDestIssuer);

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
        // Insufficient-fee attempt must leave confidential state untouched.
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);

        env(jv, Fee(10 * baseFee));
        env.close();

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == *expectedSpending);
        BEAST_EXPECT(sleBob->getFieldVL(sfIssuerEncryptedBalance) == *expectedSenderIssuer);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == *expectedInbox);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == *expectedDestIssuer);
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *sk, bal - amount));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *sk, amount));
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oa);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coa);
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

    // TransferFee mutex: create+set cannot produce confidential + nonzero fee
    // together. Covered by ConfidentialMPTIssuance_test::testTransferFeeMutex
    // and OpenLedger injection in testSendHolderLocksAndTransferFee.

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

        std::uint64_t const bal = 100;
        std::uint64_t const amount = 25;
        fundConvertMerge(env, alice, bob, mpt, bal, true);
        fundConvertMerge(env, alice, charlie, mpt, 0, true);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const senderIssuerBefore = sleBob->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const destIssuerBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const oa = (*sleIss)[sfOutstandingAmount];
        auto const coa = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const e = sigmaChallengeFromZkHex(w->zkHex);
        BEAST_EXPECT(sk && pk && e);
        auto const expectedSpending = expectSendDebit(spendingBefore, w->senderCt);
        auto const expectedSenderIssuer = expectSendDebit(senderIssuerBefore, w->issuerCt);
        auto const expectedInbox = expectSendCredit(inboxBefore, w->destCt, *pk, *e);
        auto const expectedDestIssuer = expectSendCredit(destIssuerBefore, w->issuerCt, *pk, *e);
        BEAST_EXPECT(
            expectedSpending && expectedSenderIssuer && expectedInbox && expectedDestIssuer);

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

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == *expectedSpending);
        BEAST_EXPECT(sleBob->getFieldVL(sfIssuerEncryptedBalance) == *expectedSenderIssuer);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == *expectedInbox);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == *expectedDestIssuer);
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *sk, bal - amount));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *sk, amount));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfIssuerEncryptedBalance)), *sk, bal - amount));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *sk, amount));
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oa);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coa);
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
        auto const senderIssuerBefore = sleBob->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const destIssuerBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
        auto const oa = (*sleIss)[sfOutstandingAmount];
        auto const coa = (*sleIss)[sfConfidentialOutstandingAmount];

        auto const sk = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(sk && pk && rAmt);
        // Distinct from convert/merge randomness so Enc(bal, rAmt) ≠ stored CTs.
        BEAST_EXPECT(encryptHex(bal, *pk, *rAmt) != strHex(spendingBefore));

        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), bal, bal, &*rAmt);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto const e = sigmaChallengeFromZkHex(w->zkHex);
        BEAST_EXPECT(e);
        auto const expectedSpending = expectSendDebit(spendingBefore, w->senderCt);
        auto const expectedSenderIssuer = expectSendDebit(senderIssuerBefore, w->issuerCt);
        auto const expectedInbox = expectSendCredit(inboxBefore, w->destCt, *pk, *e);
        auto const expectedDestIssuer = expectSendCredit(destIssuerBefore, w->issuerCt, *pk, *e);
        BEAST_EXPECT(
            expectedSpending && expectedSenderIssuer && expectedInbox && expectedDestIssuer);

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
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == *expectedSpending);
        BEAST_EXPECT(sleBob->getFieldVL(sfIssuerEncryptedBalance) == *expectedSenderIssuer);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == *expectedInbox);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == *expectedDestIssuer);
        // Full-balance rem=0: sender decrypts to zero; dest receives bal.
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)), *sk, 0));
        BEAST_EXPECT(
            expectDecryptsField(makeSlice(sleBob->getFieldVL(sfIssuerEncryptedBalance)), *sk, 0));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfConfidentialBalanceInbox)), *sk, bal));
        BEAST_EXPECT(expectDecryptsField(
            makeSlice(sleCharlie->getFieldVL(sfIssuerEncryptedBalance)), *sk, bal));
        BEAST_EXPECT((*sleIss)[sfOutstandingAmount] == oa);
        BEAST_EXPECT((*sleIss)[sfConfidentialOutstandingAmount] == coa);
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

    void
    testM1DestIssuerMirrorCancelTecInternal()
    {
        // Valid Send + surgically aligned dest issuer mirror so
        // mirror ⊕ amountCt ⊕ Enc(0;e) is unrepresentable. Preclaim must
        // reject with fee-claiming tecINTERNAL; confidential state unchanged.
        testcase("M1 dest issuer mirror cancel -> tecINTERNAL");
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
        // Use amount 1 (not 0): jtx rejects explicitly setting MPTAmount to default.
        fundConvertMerge(env, alice, charlie, mpt, 1);

        std::uint64_t const balance = 100;
        std::uint64_t const amount = 40;
        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), balance, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;
        BEAST_EXPECT(w->zkHex.size() >= 64);

        std::string const eHex = w->zkHex.substr(0, 64);
        auto const e = parseScalarHex(eHex.c_str());
        auto const rAmt = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        BEAST_EXPECT(e && rAmt && pk);
        if (!e || !rAmt || !pk)
            return;

        // issuer_mirror = Enc(0; -(r_amt + e)) so final credit C1 is infinity.
        auto const sum =
            fieldAdd(Secp256k1Field::fromScalar(*rAmt), Secp256k1Field::fromScalar(*e));
        auto const mirrorR = fieldNegate(sum).toScalar();
        BEAST_EXPECT(mirrorR);
        if (!mirrorR)
            return;
        auto const issuerMirrorHex = encryptHex(0, *pk, *mirrorR);
        auto const bytes = strUnHex(issuerMirrorHex);
        BEAST_EXPECT(bytes);
        if (!bytes)
            return;

        // Do not env.close() before Send — close rebuilds the open ledger.
        auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            if (!sle)
                return false;
            auto replacement = std::make_shared<SLE>(*sle, sle->key());
            replacement->setFieldVL(sfIssuerEncryptedBalance, *bytes);
            view.rawReplace(replacement);
            return true;
        });
        BEAST_EXPECT(ok);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerMirrorBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const balBefore = env.balance(bob);
        auto const seqBefore = env.seq(bob);
        auto const fee = 10 * env.current()->fees().base;

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
            Fee(fee),
            Ter(tecINTERNAL));

        BEAST_EXPECT(env.balance(bob) == balBefore - fee);
        BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == issuerMirrorBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testM1DestAuditorMirrorCancelTecInternal()
    {
        // Auditor-only M1: leave dest issuer mirror representable, surgically
        // set auditor mirror so mirror ⊕ auditorAmountCt ⊕ Enc(0;e) is
        // unrepresentable → fee-claiming tecINTERNAL from the auditor gate.
        testcase("M1 dest auditor mirror cancel -> tecINTERNAL");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const balance = 100;
        std::uint64_t const amount = 40;
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
        if (!sk || !pk || !auditorPk || !r)
            return;

        auto fundWithAuditor = [&](Account const& holder, std::uint64_t amt) {
            mpt.authorize({.account = holder});
            if (amt > 0)
                mpt.pay(alice, holder, amt > 1000 ? amt : 1000);
            auto const holderCt = encryptHex(amt, *pk, *r);
            auto const issuerCt = encryptHex(amt, *pk, *r);
            auto const auditorCt = encryptHex(amt, *auditorPk, *r);
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
                    amt,
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

        fundWithAuditor(bob, balance);
        // amount 1 avoids jtx default-MPTAmount rejection on convert.
        fundWithAuditor(charlie, 1);

        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rAmt);
        if (!rAmt)
            return;
        auto const w = buildSendWitness(
            env, bob, charlie, mpt.issuanceID(), balance, amount, &*rAmt, *auditorPk);
        BEAST_EXPECT(w && w->auditorCt);
        if (!w || !w->auditorCt)
            return;
        BEAST_EXPECT(w->zkHex.size() >= 64);

        std::string const eHex = w->zkHex.substr(0, 64);
        auto const e = parseScalarHex(eHex.c_str());
        BEAST_EXPECT(e);
        if (!e)
            return;

        // auditor_mirror = Enc(0; -(r_amt + e)) so final credit C1 is infinity.
        auto const sum =
            fieldAdd(Secp256k1Field::fromScalar(*rAmt), Secp256k1Field::fromScalar(*e));
        auto const mirrorR = fieldNegate(sum).toScalar();
        BEAST_EXPECT(mirrorR);
        if (!mirrorR)
            return;
        auto const auditorMirrorHex = encryptHex(0, *auditorPk, *mirrorR);
        auto const bytes = strUnHex(auditorMirrorHex);
        BEAST_EXPECT(bytes);
        if (!bytes)
            return;

        auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            if (!sle)
                return false;
            auto replacement = std::make_shared<SLE>(*sle, sle->key());
            replacement->setFieldVL(sfAuditorEncryptedBalance, *bytes);
            view.rawReplace(replacement);
            return true;
        });
        BEAST_EXPECT(ok);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerMirrorBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto const auditorMirrorBefore = sleCharlie->getFieldVL(sfAuditorEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const balBefore = env.balance(bob);
        auto const seqBefore = env.seq(bob);
        auto const fee = 10 * env.current()->fees().base;

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
            Fee(fee),
            Ter(tecINTERNAL));

        BEAST_EXPECT(env.balance(bob) == balBefore - fee);
        BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == issuerMirrorBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfAuditorEncryptedBalance) == auditorMirrorBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testActualOverdraft()
    {
        // Real spending = 10, claim amount = 20. Compact sigma verifies;
        // foreign aggregated BP fails verifyRange64Aggregated → tecBAD_PROOF.
        // State unchanged. Deleting the production range check would let this
        // transaction succeed.
        testcase("actual overdraft reaches range verifier -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const balance = 10;
        std::uint64_t const amount = 20;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, balance);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerBefore = sleBob->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

        auto const w =
            buildOverdraftSendWitness(env, bob, charlie, mpt.issuanceID(), balance, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;

        auto const fee = 10 * env.current()->fees().base;
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
            Fee(fee),
            Ter(tecBAD_PROOF));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleBob->getFieldVL(sfIssuerEncryptedBalance) == issuerBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testBalanceCommitmentBinding()
    {
        // Claimed balance ≠ on-ledger spending plaintext; amount is not an
        // overdraft relative to the claim and the aggregated BP is valid for
        // the claim. Rejection must come from compact-sigma balance linkage
        // (tecBAD_PROOF), not from BP corruption.
        testcase("balance commitment binding -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const realBalance = 100;
        std::uint64_t const claimedBalance = 50;
        std::uint64_t const amount = 10;
        MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});

        fundConvertMerge(env, alice, bob, mpt, realBalance);
        fundConvertMerge(env, alice, charlie, mpt, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);

        // Witness uses claimedBalance against the real Enc(realBalance) spending.
        auto const w =
            buildSendWitness(env, bob, charlie, mpt.issuanceID(), claimedBalance, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;

        // Sanity: BP openings for the claim are well-formed and would verify
        // against the witness commitments (isolates failure to sigma linkage).
        {
            auto const pcMBytes = strUnHex(w->pcMHex);
            auto const pcBBytes = strUnHex(w->pcBHex);
            auto const zkBytes = strUnHex(w->zkHex);
            BEAST_EXPECT(pcMBytes && pcBBytes && zkBytes);
            if (!pcMBytes || !pcBBytes || !zkBytes)
                return;
            auto const pcM = Secp256k1Point::parse(makeSlice(*pcMBytes));
            auto const pcB = Secp256k1Point::parse(makeSlice(*pcBBytes));
            BEAST_EXPECT(pcM && pcB);
            auto const pcRem = pointSubtract(*pcB, *pcM);
            BEAST_EXPECT(pcRem);
            Slice const bp(zkBytes->data() + kSendSigmaSize, kAggregatedBulletproofSize);
            BEAST_EXPECT(verifyRange64Aggregated(*pcM, *pcRem, bp));
        }

        auto const fee = 10 * env.current()->fees().base;
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
            Fee(fee),
            Ter(tecBAD_PROOF));

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    void
    testEncZeroRerandomization()
    {
        // Successful Send with auditor: each dest credit must be
        // before ⊕ amountCt ⊕ Enc(0;e, rolePk), and must differ from the
        // naive before ⊕ amountCt so dropping any Enc(0;e) add fails the test.
        testcase("Enc(0;e) dest mirror rerandomization");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        env.fund(XRP(10000), alice, bob, charlie);
        env.close();

        std::uint64_t const balance = 100;
        std::uint64_t const amount = 40;
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
        if (!sk || !pk || !auditorPk || !r)
            return;

        auto fundWithAuditor = [&](Account const& holder, std::uint64_t amt) {
            mpt.authorize({.account = holder});
            if (amt > 0)
                mpt.pay(alice, holder, amt > 1000 ? amt : 1000);
            auto const holderCt = encryptHex(amt, *pk, *r);
            auto const issuerCt = encryptHex(amt, *pk, *r);
            auto const auditorCt = encryptHex(amt, *auditorPk, *r);
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
                    amt,
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

        fundWithAuditor(bob, balance);
        fundWithAuditor(charlie, 0);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const issuerMirrorBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto const auditorMirrorBefore = sleCharlie->getFieldVL(sfAuditorEncryptedBalance);
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);

        auto const rAmt = parseScalarHex(kScalar1);
        BEAST_EXPECT(rAmt);
        if (!rAmt)
            return;
        auto const w = buildSendWitness(
            env, bob, charlie, mpt.issuanceID(), balance, amount, &*rAmt, *auditorPk);
        BEAST_EXPECT(w && w->auditorCt);
        if (!w || !w->auditorCt)
            return;
        BEAST_EXPECT(w->zkHex.size() >= 64);

        std::string const eHex = w->zkHex.substr(0, 64);
        auto const e = parseScalarHex(eHex.c_str());
        BEAST_EXPECT(e);
        if (!e)
            return;

        auto expectCredit = [&](Blob const& before,
                                std::string const& amountCtHex,
                                Secp256k1Point const& rolePk) -> std::optional<Blob> {
            auto const amountBytes = strUnHex(amountCtHex);
            if (!amountBytes)
                return std::nullopt;
            auto const amountCt = parseElGamalCiphertext(makeSlice(*amountBytes));
            auto const beforeCt = parseElGamalCiphertext(makeSlice(before));
            auto const encZero = ElGamalCiphertext::encrypt(0, rolePk, *e);
            if (!amountCt || !beforeCt || !encZero)
                return std::nullopt;
            auto const credited = amountCt->add(*encZero);
            if (!credited)
                return std::nullopt;
            auto const expected = beforeCt->add(*credited);
            if (!expected)
                return std::nullopt;
            auto const ser = expected->serialize();
            return Blob(ser.begin(), ser.end());
        };

        auto naiveCredit = [&](Blob const& before,
                               std::string const& amountCtHex) -> std::optional<Blob> {
            auto const amountBytes = strUnHex(amountCtHex);
            if (!amountBytes)
                return std::nullopt;
            return homomorphicAddCiphertexts(makeSlice(before), makeSlice(*amountBytes));
        };

        auto const expectedInbox = expectCredit(inboxBefore, w->destCt, *pk);
        auto const expectedIssuer = expectCredit(issuerMirrorBefore, w->issuerCt, *pk);
        auto const expectedAuditor = expectCredit(auditorMirrorBefore, *w->auditorCt, *auditorPk);
        auto const naiveInbox = naiveCredit(inboxBefore, w->destCt);
        auto const naiveIssuer = naiveCredit(issuerMirrorBefore, w->issuerCt);
        auto const naiveAuditor = naiveCredit(auditorMirrorBefore, *w->auditorCt);
        BEAST_EXPECT(expectedInbox && expectedIssuer && expectedAuditor);
        BEAST_EXPECT(naiveInbox && naiveIssuer && naiveAuditor);
        if (!expectedInbox || !expectedIssuer || !expectedAuditor || !naiveInbox || !naiveIssuer ||
            !naiveAuditor)
            return;
        // Enc(0;e) must change the ciphertext vs naive amount-only add.
        BEAST_EXPECT(*expectedInbox != *naiveInbox);
        BEAST_EXPECT(*expectedIssuer != *naiveIssuer);
        BEAST_EXPECT(*expectedAuditor != *naiveAuditor);

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
            Fee(10 * baseFee));
        env.close();

        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version + 1);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) != spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == *expectedInbox);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == *expectedIssuer);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfAuditorEncryptedBalance) == *expectedAuditor);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) != *naiveInbox);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) != *naiveIssuer);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfAuditorEncryptedBalance) != *naiveAuditor);
    }

public:
    void
    testSendContextAndRoleBindings()
    {
        // Internally consistent proofs for a false destination, CBS version,
        // sequence, issuance ID, or permuted dest/issuer sigma roles must not
        // apply. Also covers the explicit same-C1 gate via mismatched dest
        // randomness.
        testcase("send context/role/C1 bindings -> tecBAD_PROOF");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const charlie{"charlie"};
        Account const debbie{"debbie"};
        env.fund(XRP(10000), alice, bob, charlie, debbie);
        env.close();

        auto const holderSk = parseScalarHex(kScalar1);
        auto const holderPk = parsePointHex(kKeyG);
        auto const issuerSk = parseScalarHex(kScalar2);
        auto const issuerPk = parsePointHex(kKey2G);
        auto const rConvert = parseScalarHex(kScalar2);
        BEAST_EXPECT(holderSk && holderPk && issuerSk && issuerPk && rConvert);

        MPTTester mpt(env, alice, {.holders = {bob, charlie, debbie}, .fund = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKey2G});

        MPTTester mptOther(env, alice, {.holders = {bob}, .fund = false});
        mptOther.create(
            {.ownerCount = 2, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        mptOther.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKey2G});

        auto fund = [&](Account const& holder, std::uint64_t amount) {
            mpt.authorize({.account = holder});
            if (amount > 0)
                mpt.pay(alice, holder, amount > 1000 ? amount : 1000);
            auto const holderCt = encryptHex(amount, *holderPk, *rConvert);
            auto const issuerCt = encryptHex(amount, *issuerPk, *rConvert);
            auto const ctxID =
                jtx::cmpt::convertContextID(holder.id(), mpt.issuanceID(), env.seq(holder));
            auto const pok = proveRegisterPoK(*holderSk, *holderPk, makeSlice(ctxID));
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
        };
        fund(bob, 100);
        fund(charlie, 0);
        fund(debbie, 0);

        auto snapshot = [&]() {
            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            BEAST_EXPECT(sleBob && sleCharlie);
            return std::make_tuple(
                (*sleBob)[sfConfidentialBalanceVersion],
                sleBob->getFieldVL(sfConfidentialBalanceSpending),
                sleCharlie->getFieldVL(sfConfidentialBalanceInbox),
                sleCharlie->getFieldVL(sfIssuerEncryptedBalance));
        };
        auto const before = snapshot();
        auto const fee = Fee(10 * env.current()->fees().base);

        auto submitBad = [&](SendWitness const& w) {
            env(sendJV(
                    bob,
                    charlie,
                    mpt.issuanceID(),
                    w.senderCt,
                    w.destCt,
                    w.issuerCt,
                    w.pcBHex,
                    w.pcMHex,
                    w.zkHex),
                fee,
                Ter(tecBAD_PROOF));
        };

        {
            auto const w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk,
                debbie.id());
            BEAST_EXPECT(w);
            if (w)
                submitBad(*w);
        }
        {
            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto const version = (*sleBob)[sfConfidentialBalanceVersion];
            auto const w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk,
                std::nullopt,
                version + 1);
            BEAST_EXPECT(w);
            if (w)
                submitBad(*w);
        }
        {
            auto const w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk,
                std::nullopt,
                std::nullopt,
                env.seq(bob) + 1);
            BEAST_EXPECT(w);
            if (w)
                submitBad(*w);
        }
        {
            // Self-consistent sigma with dest/issuer roles permuted; tx fields
            // remain canonical. destPk != issuerPk so ciphertext order matters.
            auto const w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk,
                std::nullopt,
                std::nullopt,
                std::nullopt,
                true);
            BEAST_EXPECT(w);
            if (w)
            {
                auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
                auto const spending = parseElGamalCiphertext(
                    makeSlice(sleBob->getFieldVL(sfConfidentialBalanceSpending)));
                auto const pcMBytes = strUnHex(w->pcMHex);
                auto const pcBBytes = strUnHex(w->pcBHex);
                auto const senderBytes = strUnHex(w->senderCt);
                auto const destBytes = strUnHex(w->destCt);
                auto const issuerBytes = strUnHex(w->issuerCt);
                auto const zkBytes = strUnHex(w->zkHex);
                BEAST_EXPECT(
                    spending && pcMBytes && pcBBytes && senderBytes && destBytes && issuerBytes &&
                    zkBytes);
                if (spending && pcMBytes && pcBBytes && senderBytes && destBytes && issuerBytes &&
                    zkBytes)
                {
                    auto const pcM = Secp256k1Point::parse(makeSlice(*pcMBytes));
                    auto const pcB = Secp256k1Point::parse(makeSlice(*pcBBytes));
                    auto const senderCt = parseElGamalCiphertext(makeSlice(*senderBytes));
                    auto const destCt = parseElGamalCiphertext(makeSlice(*destBytes));
                    auto const issuerCt = parseElGamalCiphertext(makeSlice(*issuerBytes));
                    BEAST_EXPECT(pcM && pcB && senderCt && destCt && issuerCt);
                    std::vector<Secp256k1Point> permutedPks{*holderPk, *issuerPk, *holderPk};
                    std::vector<ElGamalCiphertext> permutedCts{*senderCt, *issuerCt, *destCt};
                    Slice const sigma(zkBytes->data(), kSendSigmaSize);
                    auto const version = (*sleBob)[sfConfidentialBalanceVersion];
                    auto const ctxID = jtx::cmpt::sendContextID(
                        bob.id(), mpt.issuanceID(), env.seq(bob), charlie.id(), version);
                    BEAST_EXPECT(verifySendSigma(
                        permutedPks,
                        *holderPk,
                        permutedCts,
                        *pcM,
                        *pcB,
                        *spending,
                        sigma,
                        makeSlice(ctxID)));
                    // Canonical ordering must fail.
                    std::vector<Secp256k1Point> canonPks{*holderPk, *holderPk, *issuerPk};
                    std::vector<ElGamalCiphertext> canonCts{*senderCt, *destCt, *issuerCt};
                    BEAST_EXPECT(!verifySendSigma(
                        canonPks,
                        *holderPk,
                        canonCts,
                        *pcM,
                        *pcB,
                        *spending,
                        sigma,
                        makeSlice(ctxID)));
                }
                submitBad(*w);
            }
        }
        {
            // Explicit C1 mismatch gate: start from a valid witness, then
            // replace dest CT with a different-r ciphertext so sameC1 fails
            // before sigma verify. proveSendSigma cannot build mismatched C1.
            auto w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk);
            BEAST_EXPECT(w);
            auto const rDest = parseScalarHex(kScalar3);
            BEAST_EXPECT(rDest);
            if (w && rDest)
            {
                w->destCt = encryptHex(25, *holderPk, *rDest);
                BEAST_EXPECT(!w->destCt.empty());
                BEAST_EXPECT(w->destCt != w->senderCt);
                submitBad(*w);
            }
        }
        {
            // Proof built under a different valid issuance ID in
            // confidentialTxContextID; submitted against the real issuance.
            auto const w = buildSendWitness(
                env,
                bob,
                charlie,
                mpt.issuanceID(),
                100,
                25,
                nullptr,
                std::nullopt,
                nullptr,
                &*holderSk,
                &*holderPk,
                &*holderPk,
                &*issuerPk,
                std::nullopt,
                std::nullopt,
                std::nullopt,
                false,
                nullptr,
                mptOther.issuanceID());
            BEAST_EXPECT(w);
            if (w)
                submitBad(*w);
        }

        BEAST_EXPECT(snapshot() == before);
    }

    void
    testSendInboxFinalAddInfinity()
    {
        // Align dest inbox so inbox ⊕ (destCt ⊕ Enc(0;e)) is unrepresentable
        // (C1 infinity). Must return tecBAD_PROOF with confidential state
        // unchanged (distinct from mirror tecINTERNAL paths).
        testcase("send inbox final-add infinity -> tecBAD_PROOF");
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
        // amount 1 avoids jtx default-MPTAmount rejection on convert.
        fundConvertMerge(env, alice, charlie, mpt, 1);

        std::uint64_t const balance = 100;
        std::uint64_t const amount = 40;
        auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), balance, amount);
        BEAST_EXPECT(w);
        if (!w)
            return;
        BEAST_EXPECT(w->zkHex.size() >= 64);

        std::string const eHex = w->zkHex.substr(0, 64);
        auto const e = parseScalarHex(eHex.c_str());
        auto const rAmt = parseScalarHex(kScalar1);
        auto const pk = parsePointHex(kKeyG);
        BEAST_EXPECT(e && rAmt && pk);
        if (!e || !rAmt || !pk)
            return;

        auto const sum =
            fieldAdd(Secp256k1Field::fromScalar(*rAmt), Secp256k1Field::fromScalar(*e));
        auto const inboxR = fieldNegate(sum).toScalar();
        BEAST_EXPECT(inboxR);
        if (!inboxR)
            return;
        auto const inboxHex = encryptHex(0, *pk, *inboxR);
        auto const bytes = strUnHex(inboxHex);
        BEAST_EXPECT(bytes);
        if (!bytes)
            return;

        auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            if (!sle)
                return false;
            auto replacement = std::make_shared<SLE>(*sle, sle->key());
            replacement->setFieldVL(sfConfidentialBalanceInbox, *bytes);
            view.rawReplace(replacement);
            return true;
        });
        BEAST_EXPECT(ok);

        auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT(sleBob && sleCharlie);
        auto const version = (*sleBob)[sfConfidentialBalanceVersion];
        auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
        auto const issuerBefore = sleCharlie->getFieldVL(sfIssuerEncryptedBalance);
        auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
        auto const balBefore = env.balance(bob);
        auto const seqBefore = env.seq(bob);
        auto const fee = 10 * env.current()->fees().base;

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
            Fee(fee),
            Ter(tecBAD_PROOF));

        BEAST_EXPECT(env.balance(bob) == balBefore - fee);
        BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
        sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
        sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
        BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
        BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfIssuerEncryptedBalance) == issuerBefore);
        BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
    }

    // Shared three-party confidential send fixture used by rejection-gate tables.
    struct SendRejectFixture
    {
        ConfidentialMPTSend_test& suite;
        jtx::Env env;
        jtx::Account alice{"alice"};
        jtx::Account bob{"bob"};
        jtx::Account charlie{"charlie"};
        std::unique_ptr<jtx::MPTTester> mpt;
        std::optional<SendWitness> w;
        XRPAmount fee{0};

        explicit SendRejectFixture(ConfidentialMPTSend_test& s, std::uint32_t createFlags)
            : suite(s), env{s, s.withConfidential()}
        {
            using namespace jtx;
            env.fund(XRP(10000), alice, bob, charlie);
            env.close();
            mpt = std::make_unique<MPTTester>(
                env, alice, MPTInit{.holders = {bob, charlie}, .fund = false});
            mpt->create({.ownerCount = 1, .flags = createFlags});
            mpt->set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            suite.fundConvertMerge(env, alice, bob, *mpt, 100);
            suite.fundConvertMerge(env, alice, charlie, *mpt, 1);
            w = suite.buildSendWitness(env, bob, charlie, mpt->issuanceID(), 100, 10);
            fee = 10 * env.current()->fees().base;
        }

        json::Value
        jv() const
        {
            return suite.sendJV(
                bob,
                charlie,
                mpt->issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex);
        }

        auto
        snapshot() const
        {
            auto sleBob = env.le(keylet::mptoken(mpt->issuanceID(), bob.id()));
            auto sleCharlie = env.le(keylet::mptoken(mpt->issuanceID(), charlie.id()));
            return std::make_tuple(
                (*sleBob)[sfConfidentialBalanceVersion],
                sleBob->getFieldVL(sfConfidentialBalanceSpending),
                sleCharlie->getFieldVL(sfConfidentialBalanceInbox),
                sleCharlie->getFieldVL(sfIssuerEncryptedBalance));
        }
    };

    void
    testSendPreflightMalformed()
    {
        // Distinct preflight groups: missing/malformed required CTs, optional
        // auditor CT, and commitment sizes/points. Bad ZK length already covered.
        testcase("send preflight malformed fields");
        using namespace jtx;

        SendRejectFixture fx{*this, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer};
        BEAST_EXPECT(fx.w);
        if (!fx.w)
            return;

        auto const before = fx.snapshot();
        auto const fee = Fee(fx.fee);
        std::string const badCt(10, '0');
        std::string const badPoint(32, '0');  // not 33-byte compressed point
        std::string const invalidPoint =
            "020000000000000000000000000000000000000000000000000000000000000000";

        struct Case
        {
            char const* name;
            std::function<void(json::Value&)> mutate;
            TER expect;
        };
        std::vector<Case> cases = {
            {"missing sender CT",
             [](json::Value& j) { j.removeMember(sfSenderEncryptedAmount.jsonName); },
             temMALFORMED},
            {"missing dest CT",
             [](json::Value& j) { j.removeMember(sfDestinationEncryptedAmount.jsonName); },
             temMALFORMED},
            {"missing issuer CT",
             [](json::Value& j) { j.removeMember(sfIssuerEncryptedAmount.jsonName); },
             temMALFORMED},
            {"malformed sender CT",
             [&](json::Value& j) { j[sfSenderEncryptedAmount.jsonName] = badCt; },
             temBAD_CIPHERTEXT},
            {"malformed dest CT",
             [&](json::Value& j) { j[sfDestinationEncryptedAmount.jsonName] = badCt; },
             temBAD_CIPHERTEXT},
            {"malformed issuer CT",
             [&](json::Value& j) { j[sfIssuerEncryptedAmount.jsonName] = badCt; },
             temBAD_CIPHERTEXT},
            {"malformed optional auditor CT",
             [&](json::Value& j) { j[sfAuditorEncryptedAmount.jsonName] = badCt; },
             temBAD_CIPHERTEXT},
            {"short balance commitment",
             [&](json::Value& j) { j[sfBalanceCommitment.jsonName] = badPoint; },
             temMALFORMED},
            {"invalid balance commitment point",
             [&](json::Value& j) { j[sfBalanceCommitment.jsonName] = invalidPoint; },
             temMALFORMED},
            {"short amount commitment",
             [&](json::Value& j) { j[sfAmountCommitment.jsonName] = badPoint; },
             temMALFORMED},
            {"invalid amount commitment point",
             [&](json::Value& j) { j[sfAmountCommitment.jsonName] = invalidPoint; },
             temMALFORMED},
        };

        for (auto const& c : cases)
        {
            auto j = fx.jv();
            c.mutate(j);
            fx.env(j, fee, Ter(c.expect));
            BEAST_EXPECT(fx.snapshot() == before);
        }
    }

    void
    testSendCredentialRejects()
    {
        testcase("send CredentialIDs rejection gates");
        using namespace jtx;

        // checkFields: empty / duplicate / oversize → temMALFORMED (preflight).
        {
            SendRejectFixture fx{*this, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer};
            BEAST_EXPECT(fx.w);
            if (!fx.w)
                return;
            auto const before = fx.snapshot();
            auto const fee = Fee(fx.fee);
            auto const bogus = "48004829F915654A81B11C4AB8218D96FED67F209B58328A72314FB6EA288BE4";

            fx.env(fx.jv(), fee, credentials::Ids({}), Ter(temMALFORMED));
            fx.env(fx.jv(), fee, credentials::Ids({bogus, bogus}), Ter(temMALFORMED));
            {
                std::vector<std::string> tooMany(kMaxCredentialsArraySize + 1, bogus);
                for (std::size_t i = 0; i < tooMany.size(); ++i)
                    tooMany[i].back() = static_cast<char>('0' + (i % 10));
                fx.env(fx.jv(), fee, credentials::Ids(tooMany), Ter(temMALFORMED));
            }
            BEAST_EXPECT(fx.snapshot() == before);
        }

        // valid(): nonexistent / unaccepted / wrong subject → tecBAD_CREDENTIALS.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            Account const carol{"carol"};
            env.fund(XRP(10000), alice, bob, charlie, carol);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            fundConvertMerge(env, alice, bob, mpt, 100);
            fundConvertMerge(env, alice, charlie, mpt, 0);
            auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
            BEAST_EXPECT(w);
            if (!w)
                return;
            auto const fee = Fee(10 * env.current()->fees().base);
            auto snap = [&]() {
                auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
                auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
                return std::make_tuple(
                    (*sleBob)[sfConfidentialBalanceVersion],
                    sleBob->getFieldVL(sfConfidentialBalanceSpending),
                    sleCharlie->getFieldVL(sfConfidentialBalanceInbox));
            };
            auto const before = snap();
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

            auto const bogus = "48004829F915654A81B11C4AB8218D96FED67F209B58328A72314FB6EA288BE4";
            env(jv, fee, credentials::Ids({bogus}), Ter(tecBAD_CREDENTIALS));

            char const* credType = "sendCred";
            env(credentials::create(bob, carol, credType));
            env.close();
            auto const unaccepted =
                credentials::ledgerEntry(env, bob, carol, credType)[jss::result][jss::index]
                    .asString();
            env(jv, fee, credentials::Ids({unaccepted}), Ter(tecBAD_CREDENTIALS));

            env(credentials::accept(bob, carol, credType));
            env.close();
            auto const accepted =
                credentials::ledgerEntry(env, bob, carol, credType)[jss::result][jss::index]
                    .asString();
            // Wrong subject: charlie submits bob's credential id.
            auto jvWrong = sendJV(
                charlie,
                bob,
                mpt.issuanceID(),
                w->senderCt,
                w->destCt,
                w->issuerCt,
                w->pcBHex,
                w->pcMHex,
                w->zkHex);
            // Proof is for bob→charlie; this only needs credential subject gate.
            env(jvWrong, fee, credentials::Ids({accepted}), Ter(tecBAD_CREDENTIALS));
            BEAST_EXPECT(snap() == before);
        }

        // Expired credential: preclaim may pass; doApply → tecEXPIRED (fee claimed).
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            Account const carol{"carol"};
            env.fund(XRP(10000), alice, bob, charlie, carol);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            fundConvertMerge(env, alice, bob, mpt, 100);
            fundConvertMerge(env, alice, charlie, mpt, 0);

            char const* credType = "expCred";
            auto createJv = credentials::create(bob, carol, credType);
            auto const t = env.current()->header().parentCloseTime.time_since_epoch().count();
            createJv[sfExpiration.jsonName] = t + 20;
            env(createJv);
            env.close();
            env(credentials::accept(bob, carol, credType));
            env.close();
            auto const credIdx =
                credentials::ledgerEntry(env, bob, carol, credType)[jss::result][jss::index]
                    .asString();
            env.close();
            env.close();
            env.close();

            // Rebuild after bob's accept (seq++) and ledger closes so sigma binds
            // the submit sequence; expiry is enforced in doApply after preclaim.
            auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
            BEAST_EXPECT(w);
            if (!w)
                return;

            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            auto const version = (*sleBob)[sfConfidentialBalanceVersion];
            auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
            auto const inboxBefore = sleCharlie->getFieldVL(sfConfidentialBalanceInbox);
            auto const balBefore = env.balance(bob);
            auto const seqBefore = env.seq(bob);
            auto const feeAmt = 10 * env.current()->fees().base;

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
                Fee(feeAmt),
                credentials::Ids({credIdx}),
                Ter(tecEXPIRED));

            BEAST_EXPECT(env.balance(bob) == balBefore - feeAmt);
            BEAST_EXPECT(env.seq(bob) == seqBefore + 1);
            sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
            BEAST_EXPECT((*sleBob)[sfConfidentialBalanceVersion] == version);
            BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
            BEAST_EXPECT(sleCharlie->getFieldVL(sfConfidentialBalanceInbox) == inboxBefore);
        }
    }

    void
    testSendMissingObjectsAndInit()
    {
        testcase("send missing objects / confidential init groups");
        using namespace jtx;

        // Destination account absent → tecNO_TARGET.
        {
            SendRejectFixture fx{*this, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer};
            BEAST_EXPECT(fx.w);
            if (!fx.w)
                return;
            Account const ghost{"ghost"};
            auto const before = fx.snapshot();
            fx.env(
                sendJV(
                    fx.bob,
                    ghost,
                    fx.mpt->issuanceID(),
                    fx.w->senderCt,
                    fx.w->destCt,
                    fx.w->issuerCt,
                    fx.w->pcBHex,
                    fx.w->pcMHex,
                    fx.w->zkHex),
                Fee(fx.fee),
                Ter(tecNO_TARGET));
            BEAST_EXPECT(fx.snapshot() == before);
        }

        // Issuance missing → tecOBJECT_NOT_FOUND.
        {
            SendRejectFixture fx{*this, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer};
            BEAST_EXPECT(fx.w);
            if (!fx.w)
                return;
            auto const fake = makeMptID(1, fx.alice.id());
            auto const before = fx.snapshot();
            fx.env(
                sendJV(
                    fx.bob,
                    fx.charlie,
                    fake,
                    fx.w->senderCt,
                    fx.w->destCt,
                    fx.w->issuerCt,
                    fx.w->pcBHex,
                    fx.w->pcMHex,
                    fx.w->zkHex),
                Fee(fx.fee),
                Ter(tecOBJECT_NOT_FOUND));
            BEAST_EXPECT(fx.snapshot() == before);
        }

        // Confidential flag absent → tecNO_PERMISSION.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            env.fund(XRP(10000), alice, bob, charlie);
            env.close();
            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.authorize({.account = bob});
            mpt.authorize({.account = charlie});
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
                    std::string(2 * kSendZkProofSize, '0')),
                fee,
                Ter(tecNO_PERMISSION));
        }

        // Sender / destination MPToken missing.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            env.fund(XRP(10000), alice, bob, charlie);
            env.close();
            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            fundConvertMerge(env, alice, bob, mpt, 100);
            // charlie never authorized → no MPToken.
            auto const w = buildSendWitness(env, bob, bob, mpt.issuanceID(), 100, 10);
            BEAST_EXPECT(w);
            if (!w)
                return;
            auto const fee = Fee(10 * env.current()->fees().base);
            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
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
                Ter(tecOBJECT_NOT_FOUND));
            sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);

            // Destination authorized but sender missing: fund charlie, send from
            // never-authorized debbie — use unfunded-as-sender via separate account.
            Account const debbie{"debbie"};
            env.fund(XRP(10000), debbie);
            env.close();
            fundConvertMerge(env, alice, charlie, mpt, 0);
            env(sendJV(
                    debbie,
                    charlie,
                    mpt.issuanceID(),
                    w->senderCt,
                    w->destCt,
                    w->issuerCt,
                    w->pcBHex,
                    w->pcMHex,
                    w->zkHex),
                fee,
                Ter(tecOBJECT_NOT_FOUND));
        }

        // Sender/dest missing each required confidential-init field (OpenLedger).
        {
            SendRejectFixture fx{*this, tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer};
            BEAST_EXPECT(fx.w);
            if (!fx.w)
                return;
            auto const fee = Fee(fx.fee);

            struct FieldCase
            {
                char const* name;
                bool sender;
                SF_VL const* field;
            };
            FieldCase fields[] = {
                {"sender HolderEncryptionKey", true, &sfHolderEncryptionKey},
                {"sender ConfidentialBalanceSpending", true, &sfConfidentialBalanceSpending},
                {"sender IssuerEncryptedBalance", true, &sfIssuerEncryptedBalance},
                {"dest HolderEncryptionKey", false, &sfHolderEncryptionKey},
                {"dest ConfidentialBalanceInbox", false, &sfConfidentialBalanceInbox},
                {"dest IssuerEncryptedBalance", false, &sfIssuerEncryptedBalance},
            };

            for (auto const& fc : fields)
            {
                auto const before = fx.snapshot();
                auto const account = fc.sender ? fx.bob.id() : fx.charlie.id();
                auto const key = keylet::mptoken(fx.mpt->issuanceID(), account);
                auto const saved = std::make_shared<SLE>(*fx.env.le(key), key.key);
                auto const ok =
                    fx.env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                        auto const sle = view.read(key);
                        if (!sle)
                            return false;
                        auto replacement = std::make_shared<SLE>(*sle, sle->key());
                        replacement->makeFieldAbsent(*fc.field);
                        view.rawReplace(replacement);
                        return true;
                    });
                BEAST_EXPECT(ok);
                fx.env(fx.jv(), fee, Ter(tecNO_PERMISSION));
                // Restore stripped field before snapshot (getFieldVL throws if absent).
                auto const restored =
                    fx.env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                        view.rawReplace(std::make_shared<SLE>(*saved, saved->key()));
                        return true;
                    });
                BEAST_EXPECT(restored);
                BEAST_EXPECT(fx.snapshot() == before);
            }
        }

        // Auditor key/amount mismatch + destination auditor mirror absent.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            env.fund(XRP(10000), alice, bob, charlie);
            env.close();

            // Issuance has auditor key; send omits auditor amount.
            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G});
            auto const sk = parseScalarHex(kScalar1);
            auto const pk = parsePointHex(kKeyG);
            auto const auditorPk = parsePointHex(kKey2G);
            auto const r = parseScalarHex(kScalar2);
            auto fundAud = [&](Account const& holder, std::uint64_t amount) {
                mpt.authorize({.account = holder});
                if (amount > 0)
                    mpt.pay(alice, holder, 1000);
                auto const holderCt = encryptHex(amount, *pk, *r);
                auto const issuerCt = encryptHex(amount, *pk, *r);
                auto const auditorCt = encryptHex(amount, *auditorPk, *r);
                auto const ctxID =
                    jtx::cmpt::convertContextID(holder.id(), mpt.issuanceID(), env.seq(holder));
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
            fundAud(bob, 50);
            fundAud(charlie, 1);

            auto w =
                buildSendWitness(env, bob, charlie, mpt.issuanceID(), 50, 10, nullptr, *auditorPk);
            BEAST_EXPECT(w && w->auditorCt);
            if (!w || !w->auditorCt)
                return;
            auto const fee = Fee(10 * env.current()->fees().base);
            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);

            // Has auditor key but omit amount → tecNO_PERMISSION.
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

            // No auditor key but amount present.
            {
                Env env2{*this, withConfidential()};
                Account const a{"alice"};
                Account const b{"bob"};
                Account const c{"charlie"};
                env2.fund(XRP(10000), a, b, c);
                env2.close();
                MPTTester m2(env2, a, {.holders = {b, c}, .fund = false});
                m2.create(
                    {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
                m2.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
                fundConvertMerge(env2, a, b, m2, 50);
                fundConvertMerge(env2, a, c, m2, 0);
                auto w2 = buildSendWitness(env2, b, c, m2.issuanceID(), 50, 10);
                BEAST_EXPECT(w2);
                if (!w2)
                    return;
                auto j = sendJV(
                    b,
                    c,
                    m2.issuanceID(),
                    w2->senderCt,
                    w2->destCt,
                    w2->issuerCt,
                    w2->pcBHex,
                    w2->pcMHex,
                    w2->zkHex,
                    encryptHex(10, *auditorPk, *r));
                env2(j, Fee(10 * env2.current()->fees().base), Ter(tecNO_PERMISSION));
            }

            // Destination auditor mirror absent (sender still has mirror).
            // Do not env.close() before Send — close rebuilds the open ledger.
            auto const stripped =
                env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                    auto const sle = view.read(keylet::mptoken(mpt.issuanceID(), charlie.id()));
                    if (!sle)
                        return false;
                    auto replacement = std::make_shared<SLE>(*sle, sle->key());
                    replacement->makeFieldAbsent(sfAuditorEncryptedBalance);
                    view.rawReplace(replacement);
                    return true;
                });
            BEAST_EXPECT(stripped);
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
                fee,
                Ter(tecNO_PERMISSION));
            sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        }
    }

    void
    testSendHolderLocksAndTransferFee()
    {
        testcase("send holder locks + injected TransferFee");
        using namespace jtx;

        // Holder-level sender and destination locks (issuance lock already covered).
        {
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
            auto const fee = Fee(10 * env.current()->fees().base);
            auto snap = [&]() {
                auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
                auto sleCharlie = env.le(keylet::mptoken(mpt.issuanceID(), charlie.id()));
                return std::make_tuple(
                    (*sleBob)[sfConfidentialBalanceVersion],
                    sleBob->getFieldVL(sfConfidentialBalanceSpending),
                    sleCharlie->getFieldVL(sfConfidentialBalanceInbox));
            };

            mpt.set({.account = alice, .holder = bob, .flags = tfMPTLock});
            env.close();
            auto before = snap();
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
            BEAST_EXPECT(snap() == before);

            mpt.set({.account = alice, .holder = bob, .flags = tfMPTUnlock});
            env.close();
            mpt.set({.account = alice, .holder = charlie, .flags = tfMPTLock});
            env.close();
            auto const w2 = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
            BEAST_EXPECT(w2);
            if (!w2)
                return;
            before = snap();
            env(sendJV(
                    bob,
                    charlie,
                    mpt.issuanceID(),
                    w2->senderCt,
                    w2->destCt,
                    w2->issuerCt,
                    w2->pcBHex,
                    w2->pcMHex,
                    w2->zkHex),
                fee,
                Ter(tecLOCKED));
            BEAST_EXPECT(snap() == before);
        }

        // Nonzero TransferFee is unreachable via create+set with confidential.
        // Inject via OpenLedger (same convention as COA destroy / auditor strip).
        // Rebuild SLE without SoeDefault-at-default fields — a raw SLE copy that
        // materializes TransferFee=0 throws before we can set a nonzero fee.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const charlie{"charlie"};
            env.fund(XRP(10000), alice, bob, charlie);
            env.close();
            MPTTester mpt(env, alice, {.holders = {bob, charlie}, .fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            fundConvertMerge(env, alice, bob, mpt, 100);
            fundConvertMerge(env, alice, charlie, mpt, 1);
            auto const w = buildSendWitness(env, bob, charlie, mpt.issuanceID(), 100, 10);
            BEAST_EXPECT(w);
            if (!w)
                return;

            auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                auto const sle = view.read(keylet::mptIssuance(mpt.issuanceID()));
                if (!sle)
                    return false;
                STObject fields{sfLedgerEntry};
                for (auto const& field : *sle)
                {
                    if (field.isDefault() &&
                        (field.getFName() == sfTransferFee || field.getFName() == sfAssetScale ||
                         field.getFName() == sfMutableFlags ||
                         field.getFName() == sfConfidentialOutstandingAmount))
                        continue;
                    xrpl::detail::STVar var{field};
                    fields.set(std::move(var.get()));
                }
                auto replacement = std::make_shared<SLE>(fields, sle->key());
                (*replacement)[sfTransferFee] = 100;
                view.rawReplace(replacement);
                return true;
            });
            BEAST_EXPECT(ok);
            auto sleIss = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sleIss && (*sleIss)[~sfTransferFee].value_or(0) == 100);

            auto sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            auto const spendingBefore = sleBob->getFieldVL(sfConfidentialBalanceSpending);
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
            sleBob = env.le(keylet::mptoken(mpt.issuanceID(), bob.id()));
            BEAST_EXPECT(sleBob->getFieldVL(sfConfidentialBalanceSpending) == spendingBefore);
        }
    }

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
        testM1DestIssuerMirrorCancelTecInternal();
        testM1DestAuditorMirrorCancelTecInternal();
        testActualOverdraft();
        testBalanceCommitmentBinding();
        testSendContextAndRoleBindings();
        testSendInboxFinalAddInfinity();
        testEncZeroRerandomization();
        testSendPreflightMalformed();
        testSendCredentialRejects();
        testSendMissingObjectsAndInit();
        testSendHolderLocksAndTransferFee();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSend, app, xrpl);

}  // namespace test
}  // namespace xrpl
