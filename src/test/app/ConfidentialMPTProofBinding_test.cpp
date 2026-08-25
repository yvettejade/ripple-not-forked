// Transactor-level proof binding for ConfidentialMPTSend.
//
// ConfidentialMPT_test covers the happy-path lifecycle. This suite covers the
// seams the transactor is responsible for: it rebuilds the sigma/range context
// from ledger state (spending ciphertext + ConfidentialBalanceVersion), so a
// blob that was valid for one ledger state must stop verifying once that state
// moves, and a blob assembled from two valid halves must never apply.
#include <test/jtx.h>
#include <test/jtx/fee.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/confidential.h>
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
#include <stdexcept>
#include <string>
#include <vector>

namespace xrpl::test {

class ConfidentialMPTProofBinding_test : public beast::unit_test::Suite
{
    using Scalar = confidential::Scalar;
    using CompressedPoint = confidential::CompressedPoint;
    using Ciphertext = confidential::Ciphertext;

    struct Keypair
    {
        Scalar sk{};
        CompressedPoint pk{};
    };

    static Scalar
    mustRandomScalar()
    {
        static std::uint32_t counter = 700001;
        for (std::uint32_t attempt = 0; attempt < 100000; ++attempt)
        {
            Scalar sk{};
            std::uint32_t const n = counter++;
            sk[24] = static_cast<std::uint8_t>((n >> 24) & 0xff);
            sk[25] = static_cast<std::uint8_t>((n >> 16) & 0xff);
            sk[26] = static_cast<std::uint8_t>((n >> 8) & 0xff);
            sk[27] = static_cast<std::uint8_t>(n & 0xff);
            sk[28] = 0x01;
            sk[31] = static_cast<std::uint8_t>(attempt & 0xff);
            CompressedPoint pk{};
            if (confidential::pointMulBase(sk, pk))
                return sk;
        }
        Throw<std::runtime_error>("failed to find test scalar");
        return {};
    }

    static Keypair
    makeKey()
    {
        Keypair kp;
        kp.sk = mustRandomScalar();
        if (!confidential::pointMulBase(kp.sk, kp.pk))
            Throw<std::runtime_error>("failed to derive test public key");
        return kp;
    }

    static Ciphertext
    mustEncrypt(CompressedPoint const& pk, std::uint64_t amount, Scalar const& r)
    {
        Ciphertext ct{};
        if (!confidential::elgamalEncrypt(pk, amount, r, ct))
            Throw<std::runtime_error>("failed to encrypt test amount");
        return ct;
    }

    template <std::size_t N>
    static std::string
    hexOf(std::array<std::uint8_t, N> const& a)
    {
        return strHex(Slice(a.data(), a.size()));
    }

    static std::string
    hexCipher(Ciphertext const& ct)
    {
        confidential::CiphertextBytes raw{};
        if (!confidential::serializeCiphertext(
                ct, Slice(raw.data(), raw.size())))
            Throw<std::runtime_error>("failed to serialize test ciphertext");
        return hexOf(raw);
    }

    static std::string
    rawKey(CompressedPoint const& key)
    {
        return std::string(
            reinterpret_cast<char const*>(key.data()), key.size());
    }

    // Everything needed to submit one ConfidentialMPTSend, kept so the caller
    // can resubmit or splice the ZKProof afterwards.
    struct SendMaterial
    {
        Ciphertext encSender{};
        Ciphertext encDest{};
        Ciphertext encIssuer{};
        CompressedPoint amountCommitment{};
        CompressedPoint balanceCommitment{};
        confidential::SendSigmaProof sigma{};
        std::array<std::uint8_t, confidential::kAggregatedBulletproofBytes> range{};

        std::vector<std::uint8_t>
        blob() const
        {
            std::vector<std::uint8_t> zk(confidential::kSendZkProofBytes);
            std::memcpy(zk.data(), sigma.data(), sigma.size());
            std::memcpy(zk.data() + sigma.size(), range.data(), range.size());
            return zk;
        }
    };

    void
    testProofBinding(FeatureBitset features)
    {
        testcase("send proof binds ledger state and resists splicing");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const carol("carol");
        Env env(*this, features);
        MPTTester mpt(env, gw, {.holders = {alice, carol}});
        mpt.create(
            {.pay = {{std::vector<Account>{alice, carol}, 60}},
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer |
                 tfMPTCanClawback});

        auto const issuer = makeKey();
        auto const aliceKp = makeKey();
        auto const carolKp = makeKey();
        mpt.set({.account = gw, .issuerEncryptionKey = rawKey(issuer.pk)});
        env.close();
        auto const id = mpt.issuanceID();

        auto convert = [&](Account const& acct,
                           Keypair const& kp,
                           std::uint64_t amount) {
            Scalar const r = mustRandomScalar();
            json::Value jv;
            jv[jss::TransactionType] = jss::ConfidentialMPTConvert;
            jv[jss::Account] = acct.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            jv[sfMPTAmount] = std::to_string(amount);
            jv[sfHolderEncryptedAmount] = hexCipher(mustEncrypt(kp.pk, amount, r));
            jv[sfIssuerEncryptedAmount] =
                hexCipher(mustEncrypt(issuer.pk, amount, r));
            jv[sfBlindingFactor] = to_string(uint256::fromVoid(r.data()));
            jv[sfHolderEncryptionKey] = hexOf(kp.pk);
            auto const ctxId = confidential::transactionContextIDConvert(
                static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
                Slice(acct.id().data(), acct.id().size()),
                Slice(id.data(), id.size()),
                env.seq(acct));
            confidential::SchnorrRegisterProof proof{};
            BEAST_EXPECT(confidential::proveSchnorrRegister(
                kp.sk, kp.pk, Slice(ctxId.data(), ctxId.size()), proof));
            jv[sfZKProof] = hexOf(proof);
            env(jv, Fee(XRP(1)));
            BEAST_EXPECTS(env.ter() == tesSUCCESS, transToken(env.ter()));
        };

        auto mergeInbox = [&](Account const& acct) {
            json::Value jv;
            jv[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
            jv[jss::Account] = acct.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            env(jv, Fee(XRP(1)));
            BEAST_EXPECTS(env.ter() == tesSUCCESS, transToken(env.ter()));
        };

        convert(alice, aliceKp, 60);
        mergeInbox(alice);
        convert(carol, carolKp, 0);
        mergeInbox(carol);

        // Build a Send proof against alice's *current* spending balance.
        auto buildSend = [&](std::uint64_t amount,
                             std::uint64_t balance) -> SendMaterial {
            SendMaterial m;
            Scalar const rAmt = mustRandomScalar();
            Scalar const rho = mustRandomScalar();
            m.encSender = mustEncrypt(aliceKp.pk, amount, rAmt);
            m.encDest = mustEncrypt(carolKp.pk, amount, rAmt);
            m.encIssuer = mustEncrypt(issuer.pk, amount, rAmt);
            BEAST_EXPECT(
                confidential::pedersenCommit(amount, rAmt, m.amountCommitment));
            BEAST_EXPECT(confidential::pedersenCommit(
                balance, rho, m.balanceCommitment));

            auto const sle = env.le(keylet::mptoken(id, alice.id()));
            BEAST_EXPECT(sle);
            Ciphertext spending{};
            BEAST_EXPECT(confidential::parseCiphertext(
                (*sle)[sfConfidentialBalanceSpending], spending));

            confidential::SendSigmaPublicInput pub;
            pub.recipientKeys = {aliceKp.pk, carolKp.pk, issuer.pk};
            pub.senderKey = aliceKp.pk;
            pub.c1 = m.encSender.c1;
            pub.c2 = {m.encSender.c2, m.encDest.c2, m.encIssuer.c2};
            pub.amountCommitment = m.amountCommitment;
            pub.balanceCommitment = m.balanceCommitment;
            pub.balanceC1 = spending.c1;
            pub.balanceC2 = spending.c2;

            auto const ctxId = confidential::transactionContextIDSend(
                static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
                Slice(alice.id().data(), alice.id().size()),
                Slice(id.data(), id.size()),
                env.seq(alice),
                Slice(carol.id().data(), carol.id().size()),
                (*sle)[~sfConfidentialBalanceVersion].value_or(0));

            confidential::SendSigmaWitness wit;
            wit.amount = confidential::amountToScalar(amount);
            wit.randomness = rAmt;
            wit.balance = confidential::amountToScalar(balance);
            wit.balanceBlind = rho;
            wit.senderSk = aliceKp.sk;
            BEAST_EXPECT(confidential::proveSendSigma(
                pub, wit, Slice(ctxId.data(), ctxId.size()), m.sigma));

            CompressedPoint remainder{};
            Scalar remBlind{};
            BEAST_EXPECT(confidential::pointSub(
                m.balanceCommitment, m.amountCommitment, remainder));
            BEAST_EXPECT(confidential::subScalars(rho, rAmt, remBlind));
            BEAST_EXPECT(confidential::proveBulletproofSend(
                m.amountCommitment,
                remainder,
                amount,
                balance - amount,
                rAmt,
                remBlind,
                m.range));
            return m;
        };

        auto submitSend = [&](SendMaterial const& m,
                              std::vector<std::uint8_t> const& zk,
                              TER expected) {
            json::Value jv;
            jv[jss::TransactionType] = jss::ConfidentialMPTSend;
            jv[jss::Account] = alice.human();
            jv[jss::Destination] = carol.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            jv[sfSenderEncryptedAmount] = hexCipher(m.encSender);
            jv[sfDestinationEncryptedAmount] = hexCipher(m.encDest);
            jv[sfIssuerEncryptedAmount] = hexCipher(m.encIssuer);
            jv[sfAmountCommitment] = hexOf(m.amountCommitment);
            jv[sfBalanceCommitment] = hexOf(m.balanceCommitment);
            jv[sfZKProof] = strHex(Slice(zk.data(), zk.size()));
            env(jv, Ter(expected), Fee(XRP(1)));
        };

        auto versionOf = [&](Account const& acct) -> std::uint32_t {
            auto const sle = env.le(keylet::mptoken(id, acct.id()));
            return sle ? (*sle)[~sfConfidentialBalanceVersion].value_or(0) : 0;
        };

        // A spliced blob: sigma and range proof from two independently valid
        // Sends. Each half verifies in its own context; together they must not.
        // The rejection is a tec, so it still consumes alice's sequence — every
        // later proof is therefore rebuilt against the sequence it will use.
        {
            auto const first = buildSend(10, 60);
            auto const second = buildSend(20, 60);

            std::vector<std::uint8_t> spliced(confidential::kSendZkProofBytes);
            std::memcpy(spliced.data(), first.sigma.data(), first.sigma.size());
            std::memcpy(
                spliced.data() + first.sigma.size(),
                second.range.data(),
                second.range.size());
            submitSend(first, spliced, tecBAD_PROOF);
            BEAST_EXPECT(versionOf(alice) == 1);
        }

        // Sanity: an intact blob for the current sequence still applies, and
        // advances the spending version.
        {
            auto const good = buildSend(10, 60);
            submitSend(good, good.blob(), tesSUCCESS);
            BEAST_EXPECT(versionOf(alice) == 2);
        }

        // Replay: a blob that applied once is resubmitted verbatim. The
        // transactor rebuilds the context from the account sequence and the
        // now-advanced spending state, so the old proof no longer verifies.
        // (This asserts staleness overall, not the version field in isolation —
        // ConfidentialProofCohesion covers context divergence on its own.)
        {
            auto const stale = buildSend(5, 50);
            submitSend(stale, stale.blob(), tesSUCCESS);
            BEAST_EXPECT(versionOf(alice) == 3);

            submitSend(stale, stale.blob(), tecBAD_PROOF);
            BEAST_EXPECT(versionOf(alice) == 3);
        }

        // A proof claiming more than the committed balance must not apply: the
        // remainder would wrap, so the range proof cannot be produced honestly.
        {
            auto const sle = env.le(keylet::mptoken(id, alice.id()));
            BEAST_EXPECT(sle);
            Ciphertext spending{};
            BEAST_EXPECT(confidential::parseCiphertext(
                (*sle)[sfConfidentialBalanceSpending], spending));

            Scalar const rAmt = mustRandomScalar();
            Scalar const rho = mustRandomScalar();
            std::uint64_t const amount = 10;
            std::uint64_t const overstated = 5;  // amount > balance

            CompressedPoint pcM{};
            CompressedPoint pcB{};
            BEAST_EXPECT(confidential::pedersenCommit(amount, rAmt, pcM));
            BEAST_EXPECT(confidential::pedersenCommit(overstated, rho, pcB));
            CompressedPoint remainder{};
            Scalar remBlind{};
            BEAST_EXPECT(confidential::pointSub(pcB, pcM, remainder));
            BEAST_EXPECT(confidential::subScalars(rho, rAmt, remBlind));

            // b - m underflows; proveBulletproofSend must refuse, or the
            // resulting proof must not verify against the derived remainder.
            std::array<std::uint8_t, confidential::kAggregatedBulletproofBytes>
                range{};
            bool const proved = confidential::proveBulletproofSend(
                pcM,
                remainder,
                amount,
                overstated - amount,  // wraps
                rAmt,
                remBlind,
                range);
            bool const verified = proved &&
                confidential::verifyBulletproofSend(
                    pcM, remainder, Slice(range.data(), range.size()));
            BEAST_EXPECT(!verified);
        }
    }

public:
    void
    run() override
    {
        testProofBinding(jtx::testableAmendments());
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTProofBinding, app, xrpl);

}  // namespace xrpl::test
