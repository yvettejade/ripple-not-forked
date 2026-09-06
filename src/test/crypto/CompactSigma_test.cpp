#include <test/crypto/fixtures/ConfidentialKatVectors.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/crypto/csprng.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace xrpl {
namespace {

std::array<std::uint8_t, 32>
scalarN()
{
    // secp256k1 group order n
    return {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
            0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
}

std::optional<Secp256k1Scalar>
sampleScalar()
{
    for (int i = 0; i < 64; ++i)
    {
        std::array<std::uint8_t, 32> buf{};
        cryptoPrng()(buf.data(), buf.size());
        if (auto s = Secp256k1Scalar::parse(makeSlice(buf)))
            return s;
    }
    return std::nullopt;
}

std::array<std::uint8_t, kTransactionContextIDSize>
sampleContext()
{
    std::array<std::uint8_t, kTransactionContextIDSize> id{};
    cryptoPrng()(id.data(), id.size());
    return id;
}

struct KeyPair
{
    Secp256k1Scalar sk;
    Secp256k1Point pk;
};

std::optional<KeyPair>
sampleKey()
{
    auto sk = sampleScalar();
    if (!sk)
        return std::nullopt;
    auto pk = generatorMultiply(*sk);
    if (!pk)
        return std::nullopt;
    return KeyPair{std::move(*sk), *pk};
}

void
flipByte(std::uint8_t* p, std::size_t n, std::size_t index)
{
    p[index % n] ^= 0x01;
}

}  // namespace

class CompactSigma_test : public beast::unit_test::Suite
{
public:
    void
    testPedersenAndTranscript()
    {
        testcase("Pedersen H / commit / transcript");

        auto const& H = pedersenH();
        auto const& H2 = pedersenH();
        BEAST_EXPECT(H == H2);

        auto const gBytes = std::array<std::uint8_t, 33>{
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0,
            0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
            0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
        auto const G = Secp256k1Point::parse(makeSlice(gBytes));
        BEAST_EXPECT(G);
        BEAST_EXPECT(!(H == *G));

        auto blind = sampleScalar();
        BEAST_EXPECT(blind);
        auto pc0 = pedersenCommit(0, *blind);
        BEAST_EXPECT(pc0);
        auto expect0 = pointMultiply(H, *blind);
        BEAST_EXPECT(expect0 && *pc0 == *expect0);

        auto pc5 = pedersenCommit(5, *blind);
        BEAST_EXPECT(pc5);
        BEAST_EXPECT(!(*pc5 == *pc0));

        CompactTranscript tr;
        tr.appendDomainTag("CMPT_TEST");
        tr.append(H);
        tr.append(*blind);
        tr.append(makeSlice(sampleContext()));
        auto e = tr.challenge();
        BEAST_EXPECT(e);
    }

    void
    testRegisterHonestAndTamper()
    {
        testcase("Register PoK honest / tamper");

        auto kp = sampleKey();
        auto ctx = sampleContext();
        BEAST_EXPECT(kp);

        auto proof = proveRegisterPoK(kp->sk, kp->pk, makeSlice(ctx));
        BEAST_EXPECT(proof);
        BEAST_EXPECT(proof->size() == kRegisterPoKSize);
        BEAST_EXPECT(verifyRegisterPoK(kp->pk, makeSlice(*proof), makeSlice(ctx)));

        // Tamper each scalar byte-region
        for (std::size_t off = 0; off < kRegisterPoKSize; off += 32)
        {
            auto bad = *proof;
            flipByte(bad.data(), bad.size(), off + 3);
            BEAST_EXPECT(!verifyRegisterPoK(kp->pk, makeSlice(bad), makeSlice(ctx)));
        }

        // Wrong context
        auto ctx2 = sampleContext();
        BEAST_EXPECT(!verifyRegisterPoK(kp->pk, makeSlice(*proof), makeSlice(ctx2)));

        // Wrong statement point
        auto kp2 = sampleKey();
        BEAST_EXPECT(kp2);
        BEAST_EXPECT(!verifyRegisterPoK(kp2->pk, makeSlice(*proof), makeSlice(ctx)));

        // All-zero / n-order scalars
        std::array<std::uint8_t, kRegisterPoKSize> zeroProof{};
        BEAST_EXPECT(!verifyRegisterPoK(kp->pk, makeSlice(zeroProof), makeSlice(ctx)));

        auto nProof = *proof;
        auto n = scalarN();
        std::memcpy(nProof.data(), n.data(), 32);
        BEAST_EXPECT(!verifyRegisterPoK(kp->pk, makeSlice(nProof), makeSlice(ctx)));
        std::memcpy(nProof.data() + 32, n.data(), 32);
        // restore e to something valid-looking but keep s = n
        std::memcpy(nProof.data(), proof->data(), 32);
        std::memcpy(nProof.data() + 32, n.data(), 32);
        BEAST_EXPECT(!verifyRegisterPoK(kp->pk, makeSlice(nProof), makeSlice(ctx)));
    }

    void
    testSendHonest(std::size_t nRecipients, bool amountZero)
    {
        testcase(
            std::string("Send sigma n=") + std::to_string(nRecipients) +
            (amountZero ? " amount=0" : ""));

        auto sender = sampleKey();
        BEAST_EXPECT(sender);

        std::vector<KeyPair> recipients;
        std::vector<Secp256k1Point> pks;
        for (std::size_t i = 0; i < nRecipients; ++i)
        {
            auto kp = sampleKey();
            BEAST_EXPECT(kp);
            pks.push_back(kp->pk);
            recipients.push_back(std::move(*kp));
        }

        std::uint64_t const amount = amountZero ? 0 : 42;
        std::uint64_t const balance = amountZero ? 0 : 100;
        auto r = sampleScalar();
        auto rho = sampleScalar();
        BEAST_EXPECT(r && rho);

        std::vector<ElGamalCiphertext> cts;
        for (auto const& pk : pks)
        {
            auto ct = ElGamalCiphertext::encrypt(amount, pk, *r);
            BEAST_EXPECT(ct);
            cts.push_back(*ct);
        }

        auto balCt = ElGamalCiphertext::encrypt(balance, sender->pk, *sampleScalar());
        BEAST_EXPECT(balCt);

        auto pcM = pedersenCommit(amount, *r);
        auto pcB = pedersenCommit(balance, *rho);
        BEAST_EXPECT(pcM && pcB);

        auto ctx = sampleContext();
        auto proof = proveSendSigma(
            amount,
            *r,
            balance,
            *rho,
            sender->sk,
            pks,
            sender->pk,
            cts,
            *pcM,
            *pcB,
            *balCt,
            makeSlice(ctx));
        BEAST_EXPECT(proof);
        BEAST_EXPECT(proof->size() == kSendSigmaSize);
        BEAST_EXPECT(verifySendSigma(
            pks, sender->pk, cts, *pcM, *pcB, *balCt, makeSlice(*proof), makeSlice(ctx)));

        // Tamper each proof scalar
        for (std::size_t i = 0; i < 6; ++i)
        {
            auto bad = *proof;
            flipByte(bad.data(), bad.size(), i * 32 + 1);
            BEAST_EXPECT(!verifySendSigma(
                pks, sender->pk, cts, *pcM, *pcB, *balCt, makeSlice(bad), makeSlice(ctx)));
        }

        // Tamper statement point
        BEAST_EXPECT(!verifySendSigma(
            pks, sender->pk, cts, *pcB, *pcB, *balCt, makeSlice(*proof), makeSlice(ctx)));

        // Wrong context
        auto ctx2 = sampleContext();
        BEAST_EXPECT(!verifySendSigma(
            pks, sender->pk, cts, *pcM, *pcB, *balCt, makeSlice(*proof), makeSlice(ctx2)));

        // Mismatched C1 across recipients
        if (nRecipients >= 2)
        {
            auto r2 = sampleScalar();
            BEAST_EXPECT(r2);
            auto badCt = ElGamalCiphertext::encrypt(amount, pks[1], *r2);
            BEAST_EXPECT(badCt);
            auto badCts = cts;
            badCts[1] = *badCt;
            BEAST_EXPECT(!verifySendSigma(
                pks, sender->pk, badCts, *pcM, *pcB, *balCt, makeSlice(*proof), makeSlice(ctx)));
            BEAST_EXPECT(!proveSendSigma(
                amount,
                *r,
                balance,
                *rho,
                sender->sk,
                pks,
                sender->pk,
                badCts,
                *pcM,
                *pcB,
                *balCt,
                makeSlice(ctx)));
        }

        // Reject zero / n-order proof scalars
        std::array<std::uint8_t, kSendSigmaSize> zeroProof{};
        BEAST_EXPECT(!verifySendSigma(
            pks, sender->pk, cts, *pcM, *pcB, *balCt, makeSlice(zeroProof), makeSlice(ctx)));
        auto nProof = *proof;
        auto n = scalarN();
        std::memcpy(nProof.data(), n.data(), 32);
        BEAST_EXPECT(!verifySendSigma(
            pks, sender->pk, cts, *pcM, *pcB, *balCt, makeSlice(nProof), makeSlice(ctx)));
    }

    void
    testConvertBackHonestAndZero()
    {
        testcase("ConvertBack sigma honest / amount-balance 0");

        for (std::uint64_t balance : {std::uint64_t{0}, std::uint64_t{77}})
        {
            auto sender = sampleKey();
            auto rho = sampleScalar();
            auto rBal = sampleScalar();
            BEAST_EXPECT(sender && rho && rBal);

            auto balCt = ElGamalCiphertext::encrypt(balance, sender->pk, *rBal);
            auto pcB = pedersenCommit(balance, *rho);
            BEAST_EXPECT(balCt && pcB);

            auto ctx = sampleContext();
            auto proof = proveConvertBackSigma(
                balance, *rho, sender->sk, sender->pk, *balCt, *pcB, makeSlice(ctx));
            BEAST_EXPECT(proof);
            BEAST_EXPECT(proof->size() == kConvertBackSigmaSize);
            BEAST_EXPECT(verifyConvertBackSigma(
                sender->pk, *balCt, *pcB, makeSlice(*proof), makeSlice(ctx)));

            for (std::size_t i = 0; i < 4; ++i)
            {
                auto bad = *proof;
                flipByte(bad.data(), bad.size(), i * 32 + 2);
                BEAST_EXPECT(!verifyConvertBackSigma(
                    sender->pk, *balCt, *pcB, makeSlice(bad), makeSlice(ctx)));
            }

            auto ctx2 = sampleContext();
            BEAST_EXPECT(!verifyConvertBackSigma(
                sender->pk, *balCt, *pcB, makeSlice(*proof), makeSlice(ctx2)));

            // Wrong statement
            auto other = sampleKey();
            BEAST_EXPECT(other);
            BEAST_EXPECT(!verifyConvertBackSigma(
                other->pk, *balCt, *pcB, makeSlice(*proof), makeSlice(ctx)));
        }
    }

    void
    testClawbackHonestAndTamper()
    {
        testcase("Clawback sigma honest / tamper / m=0");

        auto issuer = sampleKey();
        auto r = sampleScalar();
        BEAST_EXPECT(issuer && r);

        std::uint64_t const amount = 123;
        auto ct = ElGamalCiphertext::encrypt(amount, issuer->pk, *r);
        BEAST_EXPECT(ct);

        auto ctx = sampleContext();
        auto proof = proveClawbackSigma(amount, issuer->sk, issuer->pk, *ct, makeSlice(ctx));
        BEAST_EXPECT(proof);
        BEAST_EXPECT(proof->size() == kClawbackSigmaSize);
        BEAST_EXPECT(
            verifyClawbackSigma(amount, issuer->pk, *ct, makeSlice(*proof), makeSlice(ctx)));

        for (std::size_t i = 0; i < 2; ++i)
        {
            auto bad = *proof;
            flipByte(bad.data(), bad.size(), i * 32 + 4);
            BEAST_EXPECT(
                !verifyClawbackSigma(amount, issuer->pk, *ct, makeSlice(bad), makeSlice(ctx)));
        }

        // Wrong amount / context / key
        BEAST_EXPECT(
            !verifyClawbackSigma(amount + 1, issuer->pk, *ct, makeSlice(*proof), makeSlice(ctx)));
        auto ctx2 = sampleContext();
        BEAST_EXPECT(
            !verifyClawbackSigma(amount, issuer->pk, *ct, makeSlice(*proof), makeSlice(ctx2)));
        auto other = sampleKey();
        BEAST_EXPECT(other);
        BEAST_EXPECT(
            !verifyClawbackSigma(amount, other->pk, *ct, makeSlice(*proof), makeSlice(ctx)));

        // m = 0 rejected (spec gap: infinity not encodable)
        BEAST_EXPECT(!proveClawbackSigma(0, issuer->sk, issuer->pk, *ct, makeSlice(ctx)));
        BEAST_EXPECT(!verifyClawbackSigma(0, issuer->pk, *ct, makeSlice(*proof), makeSlice(ctx)));

        std::array<std::uint8_t, kClawbackSigmaSize> zeroProof{};
        BEAST_EXPECT(
            !verifyClawbackSigma(amount, issuer->pk, *ct, makeSlice(zeroProof), makeSlice(ctx)));
    }

    void
    testCompletenessRandom()
    {
        testcase("Completeness over random keys/amounts");

        for (int i = 0; i < 5; ++i)
        {
            auto kp = sampleKey();
            BEAST_EXPECT(kp);
            auto ctx = sampleContext();
            auto proof = proveRegisterPoK(kp->sk, kp->pk, makeSlice(ctx));
            BEAST_EXPECT(proof);
            BEAST_EXPECT(verifyRegisterPoK(kp->pk, makeSlice(*proof), makeSlice(ctx)));

            std::uint64_t const amount = 1u + static_cast<std::uint64_t>(i * 17);
            std::uint64_t const balance = amount + 50;
            auto r = sampleScalar();
            auto rho = sampleScalar();
            BEAST_EXPECT(r && rho);

            std::vector<Secp256k1Point> pks;
            std::vector<ElGamalCiphertext> cts;
            for (int j = 0; j < 3; ++j)
            {
                auto rec = sampleKey();
                BEAST_EXPECT(rec);
                pks.push_back(rec->pk);
                auto ct = ElGamalCiphertext::encrypt(amount, rec->pk, *r);
                BEAST_EXPECT(ct);
                cts.push_back(*ct);
            }
            auto balCt = ElGamalCiphertext::encrypt(balance, kp->pk, *sampleScalar());
            auto pcM = pedersenCommit(amount, *r);
            auto pcB = pedersenCommit(balance, *rho);
            BEAST_EXPECT(balCt && pcM && pcB);
            auto send = proveSendSigma(
                amount,
                *r,
                balance,
                *rho,
                kp->sk,
                pks,
                kp->pk,
                cts,
                *pcM,
                *pcB,
                *balCt,
                makeSlice(ctx));
            BEAST_EXPECT(send);
            BEAST_EXPECT(verifySendSigma(
                pks, kp->pk, cts, *pcM, *pcB, *balCt, makeSlice(*send), makeSlice(ctx)));
        }
    }

    void
    testExactSizes()
    {
        testcase("Exact proof sizes 64/192/128/64");
        BEAST_EXPECT(kRegisterPoKSize == 64);
        BEAST_EXPECT(kSendSigmaSize == 192);
        BEAST_EXPECT(kConvertBackSigmaSize == 128);
        BEAST_EXPECT(kClawbackSigmaSize == 64);
        BEAST_EXPECT(kTransactionContextIDSize == 32);
    }

    void
    testKnownAnswerPedersenTranscript()
    {
        testcase("Pedersen / hashToCurve / transcript known answers");

        using namespace test::crypto::kat;

        auto const& H = pedersenH();
        BEAST_EXPECT(H.serialize() == kPedersenH);

        std::array<std::uint8_t, 32> one{};
        one[31] = 0x01;
        std::array<std::uint8_t, 32> two{};
        two[31] = 0x02;
        auto const s1 = Secp256k1Scalar::parse(makeSlice(one));
        auto const s2 = Secp256k1Scalar::parse(makeSlice(two));
        BEAST_EXPECT(s1 && s2);

        auto const pc01 = pedersenCommit(0, *s1);
        auto const pc51 = pedersenCommit(5, *s1);
        auto const pc422 = pedersenCommit(42, *s2);
        BEAST_EXPECT(pc01 && pc51 && pc422);
        BEAST_EXPECT(pc01->serialize() == kPedersenCommit_0_1);
        BEAST_EXPECT(pc51->serialize() == kPedersenCommit_5_1);
        BEAST_EXPECT(pc422->serialize() == kPedersenCommit_42_2);

        std::string const msg = "CMPT_TEST";
        auto const hs = hashToCurveScalar(makeSlice(msg));
        BEAST_EXPECT(hs);
        BEAST_EXPECT(hs->serialize() == kHashToCurveScalar_CMPT_TEST);

        std::array<std::uint8_t, 8> raw{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        CompactTranscript tr;
        tr.appendDomainTag("CMPT_TEST");
        tr.append(H);
        tr.append(*s1);
        tr.append(makeSlice(raw));
        auto const e = tr.challenge();
        BEAST_EXPECT(e);
        BEAST_EXPECT(e->serialize() == kCompactTranscript_challenge);
    }

    void
    testKnownAnswerSigmaVerifyOnly()
    {
        testcase("Compact sigma known-answer verify-only vectors");

        using namespace test::crypto::kat;

        // Register PoK: sk=1 → pk=G, fixed context, pinned proof bytes.
        {
            auto const pk = Secp256k1Point::parse(makeSlice(kRegister_pk));
            BEAST_EXPECT(pk);
            BEAST_EXPECT(kRegister_proof.size() == kRegisterPoKSize);
            BEAST_EXPECT(verifyRegisterPoK(*pk, makeSlice(kRegister_proof), makeSlice(kSigma_ctx)));
            auto bad = kRegister_proof;
            bad[0] ^= 0x01;
            BEAST_EXPECT(!verifyRegisterPoK(*pk, makeSlice(bad), makeSlice(kSigma_ctx)));
        }

        // Send sigma: fixed statement points/ciphertexts + pinned proof.
        {
            auto const senderPk = Secp256k1Point::parse(makeSlice(kSend_senderPk));
            auto const recipientPk = Secp256k1Point::parse(makeSlice(kSend_recipientPk));
            auto const ct = ElGamalCiphertext::parse(makeSlice(kSend_ct));
            auto const balCt = ElGamalCiphertext::parse(makeSlice(kSend_balCt));
            auto const pcM = Secp256k1Point::parse(makeSlice(kSend_pcM));
            auto const pcB = Secp256k1Point::parse(makeSlice(kSend_pcB));
            BEAST_EXPECT(senderPk && recipientPk && ct && balCt && pcM && pcB);
            std::vector<Secp256k1Point> pks{*recipientPk};
            std::vector<ElGamalCiphertext> cts{*ct};
            BEAST_EXPECT(kSend_proof.size() == kSendSigmaSize);
            BEAST_EXPECT(verifySendSigma(
                pks,
                *senderPk,
                cts,
                *pcM,
                *pcB,
                *balCt,
                makeSlice(kSend_proof),
                makeSlice(kSigma_ctx)));
            auto bad = kSend_proof;
            bad[32] ^= 0x01;
            BEAST_EXPECT(!verifySendSigma(
                pks, *senderPk, cts, *pcM, *pcB, *balCt, makeSlice(bad), makeSlice(kSigma_ctx)));
        }

        // ConvertBack sigma.
        {
            auto const senderPk = Secp256k1Point::parse(makeSlice(kConvertBack_senderPk));
            auto const balCt = ElGamalCiphertext::parse(makeSlice(kConvertBack_balCt));
            auto const pcB = Secp256k1Point::parse(makeSlice(kConvertBack_pcB));
            BEAST_EXPECT(senderPk && balCt && pcB);
            BEAST_EXPECT(kConvertBack_proof.size() == kConvertBackSigmaSize);
            BEAST_EXPECT(verifyConvertBackSigma(
                *senderPk, *balCt, *pcB, makeSlice(kConvertBack_proof), makeSlice(kSigma_ctx)));
            auto bad = kConvertBack_proof;
            bad[0] ^= 0x01;
            BEAST_EXPECT(!verifyConvertBackSigma(
                *senderPk, *balCt, *pcB, makeSlice(bad), makeSlice(kSigma_ctx)));
        }

        // Clawback sigma: amount=11.
        {
            auto const pk = Secp256k1Point::parse(makeSlice(kClawback_pk));
            auto const ct = ElGamalCiphertext::parse(makeSlice(kClawback_ct));
            BEAST_EXPECT(pk && ct);
            BEAST_EXPECT(kClawback_proof.size() == kClawbackSigmaSize);
            BEAST_EXPECT(verifyClawbackSigma(
                11, *pk, *ct, makeSlice(kClawback_proof), makeSlice(kSigma_ctx)));
            auto bad = kClawback_proof;
            bad[31] ^= 0x01;
            BEAST_EXPECT(!verifyClawbackSigma(11, *pk, *ct, makeSlice(bad), makeSlice(kSigma_ctx)));
        }
    }

    void
    run() override
    {
        testExactSizes();
        testPedersenAndTranscript();
        testKnownAnswerPedersenTranscript();
        testKnownAnswerSigmaVerifyOnly();
        testRegisterHonestAndTamper();
        testSendHonest(3, false);
        testSendHonest(3, true);
        testSendHonest(4, false);
        testConvertBackHonestAndZero();
        testClawbackHonestAndTamper();
        testCompletenessRandom();
    }
};

BEAST_DEFINE_TESTSUITE(CompactSigma, crypto, xrpl);

}  // namespace xrpl
