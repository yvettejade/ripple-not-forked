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

}  // namespace

class Bulletproofs_test : public beast::unit_test::Suite
{
    void
    testSizes()
    {
        testcase("proof sizes");
        BEAST_EXPECT(kSingleBulletproofSize == 16 * 33 + 5 * 32);
        BEAST_EXPECT(kAggregatedBulletproofSize == 18 * 33 + 5 * 32);
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
    run() override
    {
        testSizes();
        testSingleRange();
        testAggregatedRange();
        testWrongWitnessRejected();
        testShortProofRejected();
    }
};

BEAST_DEFINE_TESTSUITE(Bulletproofs, crypto, xrpl);

}  // namespace xrpl
