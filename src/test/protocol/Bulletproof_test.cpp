#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Bulletproof.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace xrpl::confidential {

class Bulletproof_test : public beast::unit_test::Suite
{
    // Proofs from an independent Python implementation of the paper's
    // prover with the same transcript and serialization, using
    // deterministic randomness.
    static constexpr char const* kSingle =
        "02E73ED8335E920478B44D72A213F4126A02381C70C1846A319F766EB2FAB740"
        "3C023D57AB000F1D00109BA5D94D79EB26214BBF65083C9BE92B7D30B5502F0A"
        "E38D0273E99E06A68F10C86BD21D7F426EE92DE64239A657DC211123C839807B"
        "46F79303BDE8C1F9C4DD55846CF2E647A879089C82E1BB7CF65A6B45A72E4B5F"
        "382AAF49BD3BDFEDD885FDA519DC51C0E9D2529D1AB390D0DFDF5A5B86525634"
        "3E08EFCF831B0A55C7BBCAC3308EE93F3009F15ED87BB147C0F118ADEF2281DA"
        "7623479B632CBA96D4A42E9D8EBEF6EF407C1FC6CE70FCF27DDEC96093D9E748"
        "D5477D470269FEBB2468B59AF8AB22AEBB0D205FE98086D6EA849C9743D7D66B"
        "EE124D3F43020D4D83BEE6AC27D4BB03B013FEFEA0513B25842252AC3E8CD377"
        "5F2F41F3B3CF02B62B3A8BAE5F8A28996048DFC86AD01274A69FE8D73678747B"
        "44225CE484999202A58B41F1AF9C853D342D3E7AAACEC71B284ECEDF968CFE18"
        "9610E0BBF076BFA90277CA35E5FAB125F2B7F7C25B486E0D3AE2A9737063DEBD"
        "F1F8CED7606F5E18DE028DBE137EA5435C8E2629A47DB5BBB15959C80C00CE1A"
        "FC924DD99651CE1136B102A919CCB0D04B111D9705324A66E27BAC768AFC85B6"
        "792CB0E0CC2CBB3E34016102D3C1E20B138193E1C273DC081007110906503D31"
        "75B14AEBDA59CD376690816E0282CD6343EF494862C40037E1540229D04048B9"
        "92B3B8A93709325E5E83E18B6902921CF90F2CA11CE7A53E580ACD77BECFEC6A"
        "08039E14E6E3C43E192DEE05B9BE02DFD39E1CCEB63A27E7F897A1EF3F77AB43"
        "94212C6C62F8D41C22C8B2165ED4F903C808A93037A509DC02B64F4F6BAFE429"
        "BA01093B4F22DE6BC009E6A1C3B3523F4CEC99316B5C5FA428C344442DA6C0D9"
        "C1DEED6329DC8A03F0996DF448B7C5D5E7735B5F43490EB0F80CEDA9361B5184"
        "904DB50E5B52EC16EF8DD8C53B8A38C4";
    static constexpr char const* kSingleCommitment =
        "02364A8C2230E2640E5F8F05F2C8931E1A5FBBE031B3B69AB9D3BC4CEE6F49BB3D";
    static constexpr char const* kAggregated =
        "0294988DF7F50D607ED7B8D194D8FC6908A2003AC2C035E04869E01270B8CF71"
        "0602B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "86740264C0644D50A1B0D9668B197A59B1C6DCE2D8A7B124B59BC5617B8A551B"
        "ECE2B103CC63AFCCC20FFA2507DDF2BE31ADE0797FE6E7308685690DEBCC028F"
        "2229C5470F31D98095465F14DEA1CF22D13E594CC5533A917A3B833D5F3216F2"
        "175E80AF54DEF7A281485999300F4DD21045A6ACE06F684089D4FE90A3C70B7B"
        "255E9B2313998F12909D5C756B6F6E5CD09EAB84C6CE0885CBD854209B04A768"
        "B3ACC54E03151A4C30383D449ED17B4A262859566F66AE6A96B255238160A7EA"
        "A3D70A72800301F3ACD54987093538E7EC3DCECEF2EA131252CF5E45408C9008"
        "61C4D62B69F403C3D4B874A6C6FB680D4D8D71228D3C47F1154E41EE80C39357"
        "9BF3ACC42EA5A103622EA8220209058A34934253D3908A496EB9BB20BD34587F"
        "5011B3B189FABC66037CA8B9763D63487A97DC91C4FDF71F1D1826959C6E30C3"
        "60A048EB371D448ADC022F0894F9416B483A6CC0D461FC85FB26E6E5F33B6082"
        "D6DCF9A354D6BE9CB3F6039592CD58904A34F970010A94896D65599A42C3E4F6"
        "2B5B0DCDDC4BD2AF3355460208CE355C71C7C4BBDC5D2A468D5FBAD27B810C74"
        "7AF43AACD6490F1CB6549505036E0D8307CB337211B2146B2B08D0A486856273"
        "73738993C0A43BCE7CC7A56D540317AF03D9E684B864FA742E3F633904E203AF"
        "4AABF02B3269BB77F57B7CE07E0703C26F45C6769F035A018B05450433AEC2D2"
        "5B1CC6C4073040F7E38F5E10C6516103214ACB553FCFEECD230697A25CE6AEFA"
        "282DF7B6C720B922539204F441E6F4CE030EF620BC55777C7FBBCE3B4A18F21B"
        "4C31B2A34E25AF6A66E8020F3740BF3E0A0371D3F285A22F808896FBEF9A2976"
        "64B55B7C8872163013E611AB55DEBE30F3DE5CC7D3A041A6F032B810964D078C"
        "B7DC7B402E3C0C43D3D251EE392A6A056BB12A302F2AF33A8703B406FDBA6DC5"
        "1A329F9CCB7DD0AA5AA45006BD5ECA401FF4";
    static constexpr char const* kAggregatedCommitment0 =
        "02C4CAE1CEEC309954F210D241516160CE7EC22DB91F1308E6BDB96740D77516AE";
    static constexpr char const* kAggregatedCommitment1 =
        "03898B88DAA25A57BAEE6FD3ADEC1B31E00B374D3EA42B0C015123B05317AA1948";
    static constexpr char const* kOrder =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    static constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

    static Scalar
    s(std::uint64_t v)
    {
        return Scalar::fromUint64(v);
    }

    static Blob
    hex(std::string const& h)
    {
        auto const b = strUnHex(h);
        if (!b)
            Throw<std::runtime_error>("bad hex");
        return *b;
    }

    static std::string
    toHex(Point const& p)
    {
        auto const b = p.bytes();
        return b ? strHex(*b) : std::string{};
    }

    static uint256
    context()
    {
        uint256 c;
        std::fill(c.begin(), c.end(), 0x42);
        return c;
    }

    bool
    verify(std::vector<Point> const& v, Slice proof, uint256 const& ctx = context())
    {
        return verifyRange(v, proof, ctx);
    }

    template <class F>
    bool
    throwsInvalid(F const& f)
    {
        try
        {
            f();
        }
        catch (std::invalid_argument const&)
        {
            return true;
        }
        return false;
    }

    void
    testReferenceVectors()
    {
        testcase("Reference vectors");

        auto const single = hex(kSingle);
        std::vector<Point> const v1{pedersenCommit(s(1000), s(0x1234))};
        BEAST_EXPECT(toHex(v1[0]) == kSingleCommitment);
        BEAST_EXPECT(single.size() == kSingleRangeProofLength);
        BEAST_EXPECT(verify(v1, makeSlice(single)));

        auto const aggregated = hex(kAggregated);
        std::vector<Point> const v2{
            pedersenCommit(s(250), s(0x1234)), pedersenCommit(s(kMax), s(0x5678))};
        BEAST_EXPECT(toHex(v2[0]) == kAggregatedCommitment0);
        BEAST_EXPECT(toHex(v2[1]) == kAggregatedCommitment1);
        BEAST_EXPECT(aggregated.size() == kAggregatedRangeProofLength);
        BEAST_EXPECT(verify(v2, makeSlice(aggregated)));
    }

    void
    testCompleteness()
    {
        testcase("Completeness");

        auto const ctx = context();
        for (std::uint64_t const v :
             {std::uint64_t{0},
              std::uint64_t{1},
              std::uint64_t{1} << 32,
              std::uint64_t{0x7FFFFFFFFFFFFFFF},
              kMax})
        {
            auto const gamma = Scalar::random();
            std::vector<std::uint64_t> const values{v};
            std::vector<Scalar> const blindings{gamma};
            auto const proof = proveRange(values, blindings, ctx);
            BEAST_EXPECT(proof.size() == kSingleRangeProofLength);
            BEAST_EXPECTS(verify({pedersenCommit(s(v), gamma)}, proof), std::to_string(v));
        }

        for (auto const& [a, b] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
                 {0, 0}, {1, kMax}, {kMax, 0}, {123456789, 987654321}})
        {
            std::vector<Scalar> const blindings{Scalar::random(), Scalar::random()};
            std::vector<std::uint64_t> const values{a, b};
            auto const proof = proveRange(values, blindings, ctx);
            BEAST_EXPECT(proof.size() == kAggregatedRangeProofLength);
            BEAST_EXPECT(verify(
                {pedersenCommit(s(a), blindings[0]), pedersenCommit(s(b), blindings[1])}, proof));
        }
    }

    void
    testSoundness()
    {
        testcase("Soundness");

        auto const ctx = context();
        auto const single = hex(kSingle);
        auto const v1 = pedersenCommit(s(1000), s(0x1234));
        auto const g = Point::generator();
        auto const h = pedersenGenerator();

        // The proof is bound to the exact commitment and context.
        BEAST_EXPECT(!verify({v1 + g}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1 - g}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1 + h}, makeSlice(single)));
        BEAST_EXPECT(!verify({Point{}}, makeSlice(single)));
        uint256 otherCtx = ctx;
        otherCtx.data()[0] ^= 1;
        BEAST_EXPECT(!verify({v1}, makeSlice(single), otherCtx));

        // A value of 1000 + 2^64 has the same low 64 bits but is out of range.
        auto const twoTo64 = s(kMax) + s(1);
        BEAST_EXPECT(!verify({v1 + twoTo64 * g}, makeSlice(single)));
        // Nor does the proof cover "negative" values.
        BEAST_EXPECT(!verify({pedersenCommit(-s(1000), s(0x1234))}, makeSlice(single)));

        // The commitment count must match the proof.
        BEAST_EXPECT(!verify({}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1, v1}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1, v1, v1}, makeSlice(single)));

        auto const aggregated = hex(kAggregated);
        auto const a0 = pedersenCommit(s(250), s(0x1234));
        auto const a1 = pedersenCommit(s(kMax), s(0x5678));
        BEAST_EXPECT(!verify({a1, a0}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0, a1 + g}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0 + g, a1}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0, a1}, makeSlice(aggregated), otherCtx));

        // An honest proof of one value does not transfer to another.
        std::vector<std::uint64_t> const values{7};
        std::vector<Scalar> const blindings{s(99)};
        auto const proof = proveRange(values, blindings, ctx);
        BEAST_EXPECT(verify({pedersenCommit(s(7), s(99))}, proof));
        BEAST_EXPECT(!verify({pedersenCommit(s(8), s(99))}, proof));
        BEAST_EXPECT(!verify({pedersenCommit(s(7), s(98))}, proof));
    }

    void
    testTampering()
    {
        testcase("Tampering");

        auto const single = hex(kSingle);
        std::vector<Point> const v1{pedersenCommit(s(1000), s(0x1234))};
        for (std::size_t i = 0; i < single.size(); ++i)
        {
            Blob bad = single;
            bad[i] ^= 0x01;
            BEAST_EXPECTS(!verify(v1, makeSlice(bad)), std::to_string(i));
        }

        auto const aggregated = hex(kAggregated);
        std::vector<Point> const v2{
            pedersenCommit(s(250), s(0x1234)), pedersenCommit(s(kMax), s(0x5678))};
        for (std::size_t i = 0; i < aggregated.size(); i += 5)
        {
            Blob bad = aggregated;
            bad[i] ^= 0x80;
            BEAST_EXPECTS(!verify(v2, makeSlice(bad)), std::to_string(i));
        }

        // Lengths.
        BEAST_EXPECT(!verify(v1, Slice(single.data(), single.size() - 1)));
        Blob longer = single;
        longer.push_back(0);
        BEAST_EXPECT(!verify(v1, makeSlice(longer)));
        BEAST_EXPECT(!verify(v2, makeSlice(single)));
        BEAST_EXPECT(!verify(v1, makeSlice(aggregated)));

        // Non-canonical scalars at tau_x, mu, t_hat, a and b.
        auto const order = hex(kOrder);
        std::size_t const scalarsAt = 4 * kEcPointLength;
        std::size_t const tailAt = single.size() - 2 * kScalarLength;
        for (std::size_t const pos :
             {scalarsAt,
              scalarsAt + kScalarLength,
              scalarsAt + 2 * kScalarLength,
              tailAt,
              tailAt + kScalarLength})
        {
            Blob bad = single;
            std::copy(order.begin(), order.end(), bad.begin() + pos);
            BEAST_EXPECTS(!verify(v1, makeSlice(bad)), std::to_string(pos));
        }

        // Invalid point encodings at A, S, T1, T2 and the first L and R.
        std::size_t const lrAt = scalarsAt + 3 * kScalarLength;
        for (std::size_t const pos :
             {std::size_t{0},
              kEcPointLength,
              2 * kEcPointLength,
              3 * kEcPointLength,
              lrAt,
              lrAt + kEcPointLength})
        {
            Blob bad = single;
            bad[pos] = 0x04;
            BEAST_EXPECTS(!verify(v1, makeSlice(bad)), std::to_string(pos));
        }
    }

    void
    testProverArguments()
    {
        testcase("Prover arguments");

        auto const ctx = context();
        std::vector<std::uint64_t> const none;
        std::vector<Scalar> const noBlind;
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(none, noBlind, ctx); }));
        std::vector<std::uint64_t> const three{1, 2, 3};
        std::vector<Scalar> const threeBlind{s(1), s(2), s(3)};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(three, threeBlind, ctx); }));
        std::vector<std::uint64_t> const two{1, 2};
        std::vector<Scalar> const oneBlind{s(1)};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(two, oneBlind, ctx); }));
        std::vector<std::uint64_t> const zero{0};
        std::vector<Scalar> const zeroBlind{Scalar{}};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(zero, zeroBlind, ctx); }));
    }

public:
    void
    run() override
    {
        testReferenceVectors();
        testCompleteness();
        testSoundness();
        testTampering();
        testProverArguments();
    }
};

BEAST_DEFINE_TESTSUITE(Bulletproof, protocol, xrpl);

}  // namespace xrpl::confidential
