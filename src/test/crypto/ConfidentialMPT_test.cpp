#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/beast/utility/rngfill.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/crypto/csprng.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xrpl {
namespace {

using namespace confidential_mpt;

Scalar
randScalar()
{
    Scalar s{};
    for (;;)
    {
        beast::rngfill(s.data(), s.size(), cryptoPrng());
        if (isValidScalar(makeSlice(s)))
            return s;
    }
}

struct KeyPair
{
    Scalar sk{};
    Point pk{};
};

KeyPair
makeKeys()
{
    KeyPair kp;
    kp.sk = randScalar();
    auto pk = pointMulBase(kp.sk);
    if (!pk)
        throw std::runtime_error("pointMulBase failed in test");
    kp.pk = *pk;
    return kp;
}

Scalar
amountScalar(std::uint64_t v)
{
    Scalar s{};
    for (std::size_t i = 0; i < 8; ++i)
        s[31 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    return s;
}

Point
mustMulBase(Scalar const& k)
{
    auto p = pointMulBase(k);
    if (!p)
        throw std::runtime_error("pointMulBase failed");
    return *p;
}

Point
mustMul(Point const& p, Scalar const& k)
{
    auto q = pointMul(p, k);
    if (!q)
        throw std::runtime_error("pointMul failed");
    return *q;
}

Point
mustAdd(Point const& a, Point const& b)
{
    auto p = pointAdd(a, b);
    if (!p)
        throw std::runtime_error("pointAdd failed");
    return *p;
}

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    void
    testValidation()
    {
        testcase("validation");

        std::array<std::uint8_t, 32> shortPt{};
        expect(!isValidCompressedPoint(makeSlice(shortPt)));
        std::array<std::uint8_t, 31> shortSc{};
        expect(!isValidScalar(makeSlice(shortSc)));

        Scalar zero{};
        expect(!isValidScalar(makeSlice(zero)));

        auto const kp = makeKeys();
        expect(isValidScalar(makeSlice(kp.sk)));
        expect(isValidCompressedPoint(makeSlice(kp.pk)));

        Point bad = kp.pk;
        bad[0] = 0x04;
        expect(!isValidCompressedPoint(makeSlice(bad)));
    }

    void
    testCiphertextCodec()
    {
        testcase("ciphertext parse/serialize");

        auto const kp = makeKeys();
        Scalar const r = randScalar();
        auto const ct = encryptAmount(kp.pk, 42, r);
        expect(static_cast<bool>(ct));

        auto const parsed = parseCiphertext(makeSlice(*ct));
        expect(static_cast<bool>(parsed));
        expect(*parsed == *ct);

        expect(!parseCiphertext(Slice{ct->data(), ct->size() - 1}));

        Ciphertext bad = *ct;
        bad[0] = 0x00;
        expect(!parseCiphertext(makeSlice(bad)));

        // C1 should be r*G
        expect(ciphertextC1(*ct) == mustMulBase(r));
    }

    void
    testEncryptionAndHomomorphism()
    {
        testcase("encryption and homomorphism");

        auto const alice = makeKeys();
        Scalar const r1 = randScalar();
        Scalar const r2 = randScalar();

        auto const c1 = encryptAmount(alice.pk, 10, r1);
        auto const c2 = encryptAmount(alice.pk, 25, r2);
        expect(static_cast<bool>(c1));
        expect(static_cast<bool>(c2));
        expect(verifyCiphertext(alice.pk, *c1, 10, r1));
        expect(verifyCiphertext(alice.pk, *c2, 25, r2));
        expect(!verifyCiphertext(alice.pk, *c1, 11, r1));
        expect(!verifyCiphertext(alice.pk, *c1, 10, r2));

        // m = 0
        auto const c0 = encryptAmount(alice.pk, 0, r1);
        expect(static_cast<bool>(c0));
        expect(verifyCiphertext(alice.pk, *c0, 0, r1));

        auto const sum = ciphertextAdd(*c1, *c2);
        expect(static_cast<bool>(sum));
        auto const back = ciphertextSub(*sum, *c1);
        expect(static_cast<bool>(back));
        expect(verifyCiphertext(alice.pk, *back, 25, r2));

        auto const z = encryptZero(alice.pk, r1);
        expect(static_cast<bool>(z));
        expect(verifyCiphertext(alice.pk, *z, 0, r1));

        Scalar const e = randScalar();
        auto const rr = rerandomizeWithScalar(*c1, alice.pk, e);
        expect(static_cast<bool>(rr));
        expect(*rr != *c1);
        expect(verifyCiphertext(alice.pk, *c1, 10, r1));
        expect(!verifyCiphertext(alice.pk, *rr, 10, r1));
    }

    void
    testKeyRegistration()
    {
        testcase("key registration");

        auto const kp = makeKeys();
        std::string const context = "tx-keyreg-1";
        auto const proof = proveKeyRegistration(kp.sk, kp.pk, makeSlice(context));
        expect(static_cast<bool>(proof));
        expect(proof->size() == kKeyRegProofBytes);
        expect(verifyKeyRegistration(kp.pk, makeSlice(*proof), makeSlice(context)));

        std::string const otherCtx = "other";
        expect(!verifyKeyRegistration(kp.pk, makeSlice(*proof), makeSlice(otherCtx)));

        auto tampered = *proof;
        tampered[0] ^= 0xff;
        expect(!verifyKeyRegistration(kp.pk, makeSlice(tampered), makeSlice(context)));

        auto const other = makeKeys();
        expect(!verifyKeyRegistration(other.pk, makeSlice(*proof), makeSlice(context)));

        auto zeroed = *proof;
        std::memset(zeroed.data(), 0, kScalarBytes);
        expect(!verifyKeyRegistration(kp.pk, makeSlice(zeroed), makeSlice(context)));
    }

    void
    testSendSigma()
    {
        testcase("send compact sigma");

        auto const sender = makeKeys();
        auto const recv1 = makeKeys();
        auto const recv2 = makeKeys();

        std::uint64_t const m = 100;
        std::uint64_t const b = 500;
        Scalar const r = randScalar();
        Scalar const rho = randScalar();

        Point const c1 = mustMulBase(r);

        auto makeC2 = [&](Point const& pk) {
            Point const rPk = mustMul(pk, r);
            if (m == 0)
                return rPk;
            return mustAdd(mustMulBase(amountScalar(m)), rPk);
        };

        // B2 = b·G + sk·B1 with B1 = rhoBal·G
        Scalar const rhoBal = randScalar();
        Point const B1 = mustMulBase(rhoBal);
        Point const B2 = mustAdd(mustMulBase(amountScalar(b)), mustMul(B1, sender.sk));

        auto const PCm = pedersenCommit(m, r);
        auto const PCb = pedersenCommit(b, rho);
        expect(static_cast<bool>(PCm));
        expect(static_cast<bool>(PCb));

        SendPublicInput x;
        x.recipientKeys = {recv1.pk, recv2.pk, sender.pk};
        x.senderKey = sender.pk;
        x.c1 = c1;
        x.c2 = {makeC2(recv1.pk), makeC2(recv2.pk), makeC2(sender.pk)};
        x.amountCommitment = *PCm;
        x.balanceCommitment = *PCb;
        x.balanceC1 = B1;
        x.balanceC2 = B2;

        SendWitness w;
        w.m = m;
        w.r = r;
        w.b = b;
        w.rho = rho;
        w.sk = sender.sk;

        std::string const context = "send-ctx-v1";
        auto const proof = proveSendSigma(x, w, makeSlice(context));
        expect(static_cast<bool>(proof));
        expect(proof->size() == kSendSigmaBytes);

        auto const vr = verifySendSigma(x, makeSlice(*proof), makeSlice(context));
        expect(vr.ok);
        expect(isValidScalar(makeSlice(vr.challenge)));

        auto const inbox = encryptAmount(recv1.pk, m, r);
        expect(static_cast<bool>(inbox));
        auto const rr = rerandomizeWithScalar(*inbox, recv1.pk, vr.challenge);
        expect(static_cast<bool>(rr));

        std::string const badCtx = "nope";
        expect(!verifySendSigma(x, makeSlice(*proof), makeSlice(badCtx)).ok);

        auto tampered = *proof;
        tampered[5] ^= 0x01;
        expect(!verifySendSigma(x, makeSlice(tampered), makeSlice(context)).ok);

        expect(!verifySendSigma(x, Slice{proof->data(), 31}, makeSlice(context)).ok);

        std::vector<std::uint8_t> blob(proof->begin(), proof->end());
        blob.insert(blob.end(), {0xAA, 0xBB, 0xCC});
        auto const view = splitSendProof(makeSlice(blob));
        expect(static_cast<bool>(view));
        expect(view->sigma.size() == kSendSigmaBytes);
        expect(view->rangeProof.size() == 3);
        expect(verifySendSigma(x, view->sigma, makeSlice(context)).ok);
    }

    void
    testConvertBackSigma()
    {
        testcase("convertback balance sigma");

        auto const holder = makeKeys();
        std::uint64_t const b = 777;
        Scalar const rho = randScalar();
        Scalar const rhoBal = randScalar();

        Point const B1 = mustMulBase(rhoBal);
        Point const B2 = mustAdd(mustMulBase(amountScalar(b)), mustMul(B1, holder.sk));
        auto const PCb = pedersenCommit(b, rho);
        expect(static_cast<bool>(PCb));

        ConvertBackPublicInput x;
        x.holderKey = holder.pk;
        x.balanceC1 = B1;
        x.balanceC2 = B2;
        x.balanceCommitment = *PCb;

        ConvertBackWitness w;
        w.b = b;
        w.rho = rho;
        w.sk = holder.sk;

        std::string const context = "convertback-1";
        auto const proof = proveConvertBackSigma(x, w, makeSlice(context));
        expect(static_cast<bool>(proof));
        expect(proof->size() == kConvertBackSigmaBytes);
        expect(verifyConvertBackSigma(x, makeSlice(*proof), makeSlice(context)));

        std::string const badCtx = "x";
        expect(!verifyConvertBackSigma(x, makeSlice(*proof), makeSlice(badCtx)));

        auto tampered = *proof;
        tampered[10] ^= 0x02;
        expect(!verifyConvertBackSigma(x, makeSlice(tampered), makeSlice(context)));

        std::vector<std::uint8_t> blob(proof->begin(), proof->end());
        blob.push_back(0x01);
        auto const view = splitConvertBackProof(makeSlice(blob));
        expect(static_cast<bool>(view));
        expect(view->sigma.size() == kConvertBackSigmaBytes);
        expect(view->rangeProof.size() == 1);
    }

    void
    testClawback()
    {
        testcase("clawback chaum-pedersen");

        auto const issuer = makeKeys();
        std::uint64_t const m = 12345;
        Scalar const r = randScalar();

        auto const ct = encryptAmount(issuer.pk, m, r);
        expect(static_cast<bool>(ct));

        ClawbackPublicInput x;
        x.issuerKey = issuer.pk;
        x.c1 = ciphertextC1(*ct);
        x.c2 = ciphertextC2(*ct);
        x.m = m;

        std::string const context = "claw-1";
        auto const proof = proveClawback(x, issuer.sk, makeSlice(context));
        expect(static_cast<bool>(proof));
        expect(proof->size() == kClawbackProofBytes);
        expect(verifyClawback(x, makeSlice(*proof), makeSlice(context)));

        x.m = m + 1;
        expect(!verifyClawback(x, makeSlice(*proof), makeSlice(context)));
        x.m = m;

        std::string const otherCtx = "other";
        expect(!verifyClawback(x, makeSlice(*proof), makeSlice(otherCtx)));

        auto tampered = *proof;
        tampered[20] ^= 0x7f;
        expect(!verifyClawback(x, makeSlice(tampered), makeSlice(context)));

        auto const other = makeKeys();
        x.issuerKey = other.pk;
        expect(!verifyClawback(x, makeSlice(*proof), makeSlice(context)));
    }

    void
    testPedersenH()
    {
        testcase("pedersen H");
        auto const& h1 = pedersenH();
        auto const& h2 = pedersenH();
        expect(isValidCompressedPoint(makeSlice(h1)));
        expect(h1 == h2);
    }

    void
    testSingleBulletproof()
    {
        testcase("single 64-bit bulletproof");

        std::string const ctx = "cb-bp-ctx";
        auto check = [&](std::uint64_t rem) {
            Scalar const rho = randScalar();
            auto const PCrem = pedersenCommit(rem, rho);
            expect(static_cast<bool>(PCrem));
            auto const proof = proveSingleBulletproof(*PCrem, rem, rho, makeSlice(ctx));
            expect(static_cast<bool>(proof));
            expect(proof->size() == kSingleBulletproofBytes);
            expect(proof->size() == 688);
            expect(verifySingleBulletproof(*PCrem, makeSlice(*proof), makeSlice(ctx)));

            // wrong context
            expect(!verifySingleBulletproof(
                *PCrem, makeSlice(*proof), makeSlice(std::string{"other"})));

            // wrong commitment
            auto const other = pedersenCommit(rem ^ 1ull, rho);
            expect(static_cast<bool>(other));
            expect(!verifySingleBulletproof(*other, makeSlice(*proof), makeSlice(ctx)));

            // tamper one byte in a point region and a scalar region
            auto tamp = *proof;
            tamp[10] ^= 0x01;
            expect(!verifySingleBulletproof(*PCrem, makeSlice(tamp), makeSlice(ctx)));
            tamp = *proof;
            tamp[16 * kPointBytes + 3] ^= 0x01;
            expect(!verifySingleBulletproof(*PCrem, makeSlice(tamp), makeSlice(ctx)));

            // wrong size
            expect(!verifySingleBulletproof(
                *PCrem, Slice{proof->data(), proof->size() - 1}, makeSlice(ctx)));
        };

        check(0);
        check(1);
        check(42);
        check(std::numeric_limits<std::uint64_t>::max());
    }

    void
    testAggregatedBulletproof()
    {
        testcase("aggregated two-value 64-bit bulletproof");

        std::string const ctx = "send-bp-ctx";
        auto check = [&](std::uint64_t amount, std::uint64_t rem) {
            Scalar const r = randScalar();
            Scalar const remBlind = randScalar();
            auto const PCm = pedersenCommit(amount, r);
            auto const PCrem = pedersenCommit(rem, remBlind);
            expect(static_cast<bool>(PCm));
            expect(static_cast<bool>(PCrem));

            auto const proof =
                proveAggregatedBulletproof(*PCm, *PCrem, amount, r, rem, remBlind, makeSlice(ctx));
            expect(static_cast<bool>(proof));
            expect(proof->size() == kAggregatedBulletproofBytes);
            expect(proof->size() == 754);
            expect(verifyAggregatedBulletproof(*PCm, *PCrem, makeSlice(*proof), makeSlice(ctx)));

            expect(!verifyAggregatedBulletproof(
                *PCm, *PCrem, makeSlice(*proof), makeSlice(std::string{"nope"})));

            // swapped commitments
            expect(!verifyAggregatedBulletproof(*PCrem, *PCm, makeSlice(*proof), makeSlice(ctx)));

            auto tamp = *proof;
            tamp[40] ^= 0xff;
            expect(!verifyAggregatedBulletproof(*PCm, *PCrem, makeSlice(tamp), makeSlice(ctx)));

            expect(!verifyAggregatedBulletproof(
                *PCm, *PCrem, Slice{proof->data(), 700}, makeSlice(ctx)));
        };

        check(0, 0);
        check(0, 99);
        check(1, 0);
        check(100, 400);
        check(std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max());
    }

public:
    void
    run() override
    {
        testValidation();
        testCiphertextCodec();
        testEncryptionAndHomomorphism();
        testKeyRegistration();
        testSendSigma();
        testConvertBackSigma();
        testClawback();
        testPedersenH();
        testSingleBulletproof();
        testAggregatedBulletproof();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, crypto, xrpl);

}  // namespace
}  // namespace xrpl
