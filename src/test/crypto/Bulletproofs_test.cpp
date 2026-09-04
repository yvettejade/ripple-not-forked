#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/Bulletproofs.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/crypto/csprng.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <vector>

namespace xrpl {
namespace {

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

// Fixed wire layout (no internals exposed). Point=33, scalar=32.
// A,S,T1,T2 | tauX,mu,tHat | L[rounds],R[rounds] | a,b
// Note: on-wire scalar order is tauX, mu, tHat; Fiat–Shamir binds
// tHat, tauX, mu before challenge w (Protocol 1 / §4.2).
constexpr std::size_t kPt = 33;
constexpr std::size_t kSc = 32;
constexpr std::size_t kOffA = 0;
constexpr std::size_t kOffS = kPt;
constexpr std::size_t kOffT1 = 2 * kPt;
constexpr std::size_t kOffT2 = 3 * kPt;
constexpr std::size_t kOffTauX = 4 * kPt;
constexpr std::size_t kOffMu = kOffTauX + kSc;
constexpr std::size_t kOffTHat = kOffMu + kSc;
constexpr std::size_t kOffIpa = kOffTHat + kSc;

}  // namespace

class Bulletproofs_test : public beast::unit_test::Suite
{
    void
    testSizes()
    {
        testcase("proof sizes");
        BEAST_EXPECT(kSingleBulletproofSize == 16 * 33 + 5 * 32);
        BEAST_EXPECT(kAggregatedBulletproofSize == 18 * 33 + 5 * 32);
        // 4 header pts + 2*6 IPA pts + 5 scalars (single, log2(64)=6).
        BEAST_EXPECT(kSingleBulletproofSize == 4 * kPt + 2 * 6 * kPt + 5 * kSc);
        // Aggregated m=2 → n=128, log2=7 → 4+14 pts + 5 scalars.
        BEAST_EXPECT(kAggregatedBulletproofSize == 4 * kPt + 2 * 7 * kPt + 5 * kSc);
        BEAST_EXPECT(kOffIpa == 4 * kPt + 3 * kSc);
    }

    void
    checkSingle(std::uint64_t value)
    {
        auto const gamma = sampleScalar();
        BEAST_EXPECT(gamma);
        auto const V = pedersenCommit(value, *gamma);
        BEAST_EXPECT(V);
        auto const proof = proveRange64(value, *gamma, *V);
        BEAST_EXPECT(proof);
        if (!proof)
            return;
        BEAST_EXPECT(proof->size() == kSingleBulletproofSize);
        BEAST_EXPECT(verifyRange64(*V, makeSlice(*proof)));

        auto tampered = *proof;
        tampered[0] ^= 0x01;
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(tampered)));

        auto last = *proof;
        last.back() ^= 0x01;
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(last)));

        auto const other = sampleScalar();
        BEAST_EXPECT(other);
        auto const V2 = pedersenCommit(value + 1, *other);
        BEAST_EXPECT(V2);
        BEAST_EXPECT(!verifyRange64(*V2, makeSlice(*proof)));
    }

    void
    testSingleRange()
    {
        testcase("single 64-bit range proof");
        checkSingle(0);
        checkSingle(1);
        checkSingle(42);
        checkSingle(std::uint64_t{1} << 32);
        checkSingle((std::uint64_t{1} << 63) - 1);
        checkSingle(std::numeric_limits<std::uint64_t>::max());
    }

    void
    testAggregatedRange()
    {
        testcase("aggregated two-value 64-bit range proof");
        auto const g1 = sampleScalar();
        auto const g2 = sampleScalar();
        BEAST_EXPECT(g1 && g2);
        std::uint64_t const v1 = 7;
        std::uint64_t const v2 = (std::uint64_t{1} << 40) + 9;
        auto const V1 = pedersenCommit(v1, *g1);
        auto const V2 = pedersenCommit(v2, *g2);
        BEAST_EXPECT(V1 && V2);
        auto const proof = proveRange64Aggregated(v1, *g1, *V1, v2, *g2, *V2);
        BEAST_EXPECT(proof);
        if (!proof)
            return;
        BEAST_EXPECT(proof->size() == kAggregatedBulletproofSize);
        BEAST_EXPECT(verifyRange64Aggregated(*V1, *V2, makeSlice(*proof)));

        auto bad = *proof;
        bad[33] ^= 0x02;
        BEAST_EXPECT(!verifyRange64Aggregated(*V1, *V2, makeSlice(bad)));
        BEAST_EXPECT(!verifyRange64Aggregated(*V2, *V1, makeSlice(*proof)));
        BEAST_EXPECT(!verifyRange64(*V1, makeSlice(*proof)));
    }

    void
    testWrongWitnessRejected()
    {
        testcase("commitment mismatch rejected at prove");
        auto const g = sampleScalar();
        BEAST_EXPECT(g);
        auto const V = pedersenCommit(5, *g);
        BEAST_EXPECT(V);
        BEAST_EXPECT(!proveRange64(6, *g, *V));
    }

    void
    testShortProofRejected()
    {
        testcase("truncated proof rejected");
        std::array<std::uint8_t, 10> tiny{};
        auto const g = sampleScalar();
        BEAST_EXPECT(g);
        auto const V = pedersenCommit(1, *g);
        BEAST_EXPECT(V);
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(tiny)));
        BEAST_EXPECT(!verifyRange64Aggregated(*V, *V, makeSlice(tiny)));
    }

    void
    mutateAndReject(
        Secp256k1Point const& V,
        std::array<std::uint8_t, kSingleBulletproofSize> proof,
        std::size_t offset,
        char const* label)
    {
        // Flip a mid-scalar byte so parse still succeeds but the value changes.
        proof[offset + 16] ^= 0x01;
        BEAST_EXPECT(!verifyRange64(V, makeSlice(proof)));
        (void)label;
    }

    void
    testProtocol1ScalarBinding()
    {
        // Protocol 1 binds t̂,τ_x,μ into challenge w before IPA. Mutating any of
        // those scalars (or the range header points that affect earlier
        // challenges) must fail verification — last-byte flips only hit IPA b.
        //
        // Serialization layout: A,S,T1,T2, then tauX,mu,tHat (wire order), then
        // IPA. Transcript bind order is tHat,tauX,mu — different from wire.
        //
        // Interop residual: custom NUMS generators and CompactTranscript domain
        // tags are not prescribed by the paper, so fixed cross-library proof
        // vectors are unavailable; this is transcript/generator uncertainty,
        // not algebraic Protocol 1 uncertainty. Old-format proofs (no w) also
        // cannot be tested with a canned vector for the same reason.
        testcase("Protocol 1 scalar and header binding");
        auto const gamma = sampleScalar();
        BEAST_EXPECT(gamma);
        auto const V = pedersenCommit(99, *gamma);
        BEAST_EXPECT(V);
        auto const proof = proveRange64(99, *gamma, *V);
        BEAST_EXPECT(proof);
        if (!proof)
            return;
        BEAST_EXPECT(verifyRange64(*V, makeSlice(*proof)));

        mutateAndReject(*V, *proof, kOffA, "A");
        mutateAndReject(*V, *proof, kOffS, "S");
        mutateAndReject(*V, *proof, kOffT1, "T1");
        mutateAndReject(*V, *proof, kOffT2, "T2");
        mutateAndReject(*V, *proof, kOffTauX, "tauX");
        mutateAndReject(*V, *proof, kOffMu, "mu");
        mutateAndReject(*V, *proof, kOffTHat, "tHat");
    }

    void
    testProofLayoutParser()
    {
        testcase("fixed proof layout size and parse gates");
        auto const g = sampleScalar();
        BEAST_EXPECT(g);
        auto const V = pedersenCommit(3, *g);
        BEAST_EXPECT(V);
        auto const proof = proveRange64(3, *g, *V);
        BEAST_EXPECT(proof);
        if (!proof)
            return;

        // Exact size required.
        BEAST_EXPECT(proof->size() == kSingleBulletproofSize);
        std::vector<std::uint8_t> shortProof(
            proof->begin(), proof->begin() + kSingleBulletproofSize - 1);
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(shortProof)));

        std::vector<std::uint8_t> longProof(proof->begin(), proof->end());
        longProof.push_back(0);
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(longProof)));

        // Corrupt compressed point prefix at A → parse/verify fail.
        auto badPt = *proof;
        badPt[kOffA] = 0x00;
        BEAST_EXPECT(!verifyRange64(*V, makeSlice(badPt)));

        auto const g2 = sampleScalar();
        BEAST_EXPECT(g2);
        auto const V1 = pedersenCommit(1, *g);
        auto const V2 = pedersenCommit(2, *g2);
        BEAST_EXPECT(V1 && V2);
        auto const ag = proveRange64Aggregated(1, *g, *V1, 2, *g2, *V2);
        BEAST_EXPECT(ag);
        if (ag)
        {
            BEAST_EXPECT(ag->size() == kAggregatedBulletproofSize);
            std::vector<std::uint8_t> shortAgg(ag->begin(), ag->end() - 1);
            BEAST_EXPECT(!verifyRange64Aggregated(*V1, *V2, makeSlice(shortAgg)));
        }
    }

    void
    run() override
    {
        testSizes();
        testSingleRange();
        testAggregatedRange();
        testWrongWitnessRejected();
        testShortProofRejected();
        testProtocol1ScalarBinding();
        testProofLayoutParser();
    }
};

BEAST_DEFINE_TESTSUITE(Bulletproofs, crypto, xrpl);

}  // namespace xrpl
