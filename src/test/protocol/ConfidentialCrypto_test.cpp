#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

namespace xrpl::confidential {

class ConfidentialCrypto_test : public beast::unit_test::Suite
{
    static constexpr char const* kG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kTwoG =
        "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
    static constexpr char const* kThreeG =
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
    static constexpr char const* kMinusG =
        "0379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kOrderMinusOne =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
    static constexpr char const* kOrder =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    static Blob
    hex(std::string const& s)
    {
        auto const blob = strUnHex(s);
        if (!blob)
            Throw<std::runtime_error>("bad hex in test vector");
        return *blob;
    }

    static Point
    point(std::string const& s)
    {
        auto const blob = hex(s);
        auto const p = Point::fromBytes(makeSlice(blob));
        if (!p)
            Throw<std::runtime_error>("bad point in test vector");
        return *p;
    }

    static std::string
    toHex(Point const& p)
    {
        auto const b = p.bytes();
        return b ? strHex(*b) : std::string{};
    }

    void
    testScalar()
    {
        testcase("Scalar");

        BEAST_EXPECT(Scalar{}.isZero());
        BEAST_EXPECT(Scalar::fromUint64(0).isZero());
        BEAST_EXPECT(!Scalar::fromUint64(1).isZero());

        {
            auto const s = Scalar::fromUint64(0x0102030405060708ULL);
            std::array<std::uint8_t, kScalarLength> expected{};
            for (std::size_t i = 0; i < 8; ++i)
                expected[kScalarLength - 8 + i] = static_cast<std::uint8_t>(i + 1);
            BEAST_EXPECT(s.bytes() == expected);

            auto const parsed = Scalar::fromBytes(makeSlice(s.bytes()));
            BEAST_EXPECT(parsed && *parsed == s);
        }

        {
            auto const max = Scalar::fromUint64(std::numeric_limits<std::uint64_t>::max());
            BEAST_EXPECT(strHex(max.bytes()) == std::string(48, '0') + std::string(16, 'F'));
        }

        // Zero, n - 1 and every value in between are canonical.
        std::array<std::uint8_t, kScalarLength> const zero{};
        BEAST_EXPECT(Scalar::fromBytes(makeSlice(zero)) == Scalar{});
        BEAST_EXPECT(Scalar::fromBytes(makeSlice(hex(kOrderMinusOne))).has_value());

        // n and anything above it is rejected rather than reduced.
        BEAST_EXPECT(!Scalar::fromBytes(makeSlice(hex(kOrder))).has_value());
        BEAST_EXPECT(!Scalar::fromBytes(makeSlice(hex(std::string(64, 'F')))).has_value());

        // Wrong lengths are rejected.
        BEAST_EXPECT(!Scalar::fromBytes(Slice{}).has_value());
        BEAST_EXPECT(!Scalar::fromBytes(makeSlice(hex(std::string(60, '0') + "01"))).has_value());
        BEAST_EXPECT(!Scalar::fromBytes(makeSlice(hex(std::string(66, '0')))).has_value());
    }

    void
    testPointEncoding()
    {
        testcase("Point encoding");

        auto const g = Point::generator();
        BEAST_EXPECT(!g.isInfinity());
        BEAST_EXPECT(toHex(g) == kG);
        BEAST_EXPECT(point(kG) == g);
        BEAST_EXPECT(isValidPoint(makeSlice(hex(kG))));
        BEAST_EXPECT(isValidPoint(makeSlice(hex(kMinusG))));

        // The identity has no compressed encoding.
        BEAST_EXPECT(Point{}.isInfinity());
        BEAST_EXPECT(!Point{}.bytes().has_value());

        // Length, prefix and curve membership are all enforced.
        auto const good = hex(kG);
        BEAST_EXPECT(!Point::fromBytes(Slice{}).has_value());
        BEAST_EXPECT(!Point::fromBytes(Slice(good.data(), good.size() - 1)).has_value());
        {
            Blob longer = good;
            longer.push_back(0);
            BEAST_EXPECT(!isValidPoint(makeSlice(longer)));
        }
        for (std::uint8_t const prefix :
             std::array<std::uint8_t, 7>{0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xFF})
        {
            Blob b = good;
            b[0] = prefix;
            BEAST_EXPECTS(!isValidPoint(makeSlice(b)), std::to_string(prefix));
        }
        // x = 0 and x = 5 are not on secp256k1; x = 2^256 - 1 exceeds p.
        BEAST_EXPECT(!isValidPoint(makeSlice(hex("02" + std::string(64, '0')))));
        BEAST_EXPECT(!isValidPoint(makeSlice(hex("03" + std::string(63, '0') + "5"))));
        BEAST_EXPECT(!isValidPoint(makeSlice(hex("02" + std::string(64, 'F')))));
        // Uncompressed encodings are not accepted even when valid.
        BEAST_EXPECT(!isValidPoint(makeSlice(
            hex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))));
    }

    void
    testPointArithmetic()
    {
        testcase("Point arithmetic");

        auto const g = Point::generator();
        auto const two = Scalar::fromUint64(2);
        auto const three = Scalar::fromUint64(3);

        BEAST_EXPECT(toHex(g + g) == kTwoG);
        BEAST_EXPECT(toHex(two * g) == kTwoG);
        BEAST_EXPECT(toHex(mulGenerator(two)) == kTwoG);
        BEAST_EXPECT(toHex(mulGenerator(three)) == kThreeG);
        BEAST_EXPECT(toHex(g + g + g) == kThreeG);
        BEAST_EXPECT(toHex(-g) == kMinusG);
        BEAST_EXPECT(point(kThreeG) - g == point(kTwoG));

        auto const orderMinusOne = Scalar::fromBytes(makeSlice(hex(kOrderMinusOne)));
        BEAST_EXPECT(orderMinusOne && toHex(mulGenerator(*orderMinusOne)) == kMinusG);
        BEAST_EXPECT(orderMinusOne && toHex(*orderMinusOne * g) == kMinusG);

        // Identity behaviour, including sums that cancel.
        Point const o;
        BEAST_EXPECT(g + o == g);
        BEAST_EXPECT(o + g == g);
        BEAST_EXPECT((o + o).isInfinity());
        BEAST_EXPECT((-o).isInfinity());
        BEAST_EXPECT((g - g).isInfinity());
        BEAST_EXPECT((g + (-g)).isInfinity());
        BEAST_EXPECT((Scalar{} * g).isInfinity());
        BEAST_EXPECT((two * o).isInfinity());
        BEAST_EXPECT(mulGenerator(Scalar{}).isInfinity());
        BEAST_EXPECT(o == Point{});
        BEAST_EXPECT(!(o == g));
        BEAST_EXPECT(!(g == o));
        BEAST_EXPECT(!(g == -g));

        // Distributivity and associativity on arbitrary multiples.
        auto const a = Scalar::fromUint64(0x1234567890ABCDEFULL);
        auto const b = Scalar::fromUint64(0x0FEDCBA987654321ULL);
        auto const aPlusB = Scalar::fromUint64(0x1234567890ABCDEFULL + 0x0FEDCBA987654321ULL);
        BEAST_EXPECT(mulGenerator(a) + mulGenerator(b) == mulGenerator(aPlusB));
        auto const p = mulGenerator(Scalar::fromUint64(987654321));
        BEAST_EXPECT(a * p + b * p == aPlusB * p);
        BEAST_EXPECT(two * (three * g) == Scalar::fromUint64(6) * g);
    }

    void
    testCiphertextEncoding()
    {
        testcase("Ciphertext encoding");

        auto const pk = mulGenerator(Scalar::fromUint64(0xC0FFEE));
        auto const ct = elGamalEncrypt(Scalar::fromUint64(42), Scalar::fromUint64(777), pk);

        auto const buf = ct.toBuffer();
        if (!BEAST_EXPECT(buf && buf->size() == kElGamalCiphertextLength))
            return;
        BEAST_EXPECT(strHex(Slice(buf->data(), kEcPointLength)) == toHex(ct.c1));
        BEAST_EXPECT(strHex(Slice(buf->data() + kEcPointLength, kEcPointLength)) == toHex(ct.c2));

        auto const parsed = ElGamalCiphertext::fromBytes(*buf);
        BEAST_EXPECT(parsed && *parsed == ct);

        // Wrong total length.
        BEAST_EXPECT(!ElGamalCiphertext::fromBytes(Slice(buf->data(), buf->size() - 1)));
        BEAST_EXPECT(!ElGamalCiphertext::fromBytes(Slice(buf->data(), kEcPointLength)));
        BEAST_EXPECT(!ElGamalCiphertext::fromBytes(Slice{}));
        {
            Blob longer(buf->data(), buf->data() + buf->size());
            longer.push_back(0x00);
            BEAST_EXPECT(!ElGamalCiphertext::fromBytes(makeSlice(longer)));
        }

        // Either half may be invalid.
        for (std::size_t const offset : {std::size_t{0}, kEcPointLength})
        {
            Blob bad(buf->data(), buf->data() + buf->size());
            bad[offset] = 0x04;
            BEAST_EXPECT(!ElGamalCiphertext::fromBytes(makeSlice(bad)));

            Blob offCurve(buf->data(), buf->data() + buf->size());
            std::fill(offCurve.begin() + offset + 1, offCurve.begin() + offset + kEcPointLength, 0);
            BEAST_EXPECT(!ElGamalCiphertext::fromBytes(makeSlice(offCurve)));
        }

        // A ciphertext with an identity component cannot be serialized.
        BEAST_EXPECT(!(ElGamalCiphertext{.c1 = Point{}, .c2 = ct.c2}.toBuffer()));
        BEAST_EXPECT(!(ElGamalCiphertext{.c1 = ct.c1, .c2 = Point{}}.toBuffer()));
        BEAST_EXPECT(!(ct - ct).toBuffer());
    }

    void
    testEncryption()
    {
        testcase("ElGamal encryption");

        auto const sk = Scalar::fromUint64(0x5EC12E7);
        auto const pk = mulGenerator(sk);
        auto const otherPk = mulGenerator(Scalar::fromUint64(0x07E12));
        auto const m = Scalar::fromUint64(1000);
        auto const r = Scalar::fromUint64(0xB11D);

        auto const ct = elGamalEncrypt(m, r, pk);
        BEAST_EXPECT(ct.c1 == mulGenerator(r));
        BEAST_EXPECT(ct.c2 == mulGenerator(m) + r * pk);

        // Decryption with the secret key recovers m·G.
        BEAST_EXPECT(ct.c2 - sk * ct.c1 == mulGenerator(m));

        BEAST_EXPECT(verifyElGamalEncryption(ct, m, r, pk));
        BEAST_EXPECT(!verifyElGamalEncryption(ct, Scalar::fromUint64(1001), r, pk));
        BEAST_EXPECT(!verifyElGamalEncryption(ct, m, Scalar::fromUint64(0xB11E), pk));
        BEAST_EXPECT(!verifyElGamalEncryption(ct, m, r, otherPk));
        BEAST_EXPECT(!verifyElGamalEncryption(ct, m, r, Point{}));
        BEAST_EXPECT(!verifyElGamalEncryption(ct, m, Scalar{}, pk));

        // Swapping components must not verify.
        BEAST_EXPECT(
            !verifyElGamalEncryption(ElGamalCiphertext{.c1 = ct.c2, .c2 = ct.c1}, m, r, pk));

        // An encryption of zero: C2 = r·pk.
        auto const zero = elGamalEncrypt(Scalar{}, r, pk);
        BEAST_EXPECT(zero.c2 == r * pk);
        BEAST_EXPECT(verifyElGamalEncryption(zero, Scalar{}, r, pk));
        BEAST_EXPECT(!verifyElGamalEncryption(zero, Scalar::fromUint64(1), r, pk));
        BEAST_EXPECT(zero.toBuffer().has_value());

        // The same (m, r) under different keys shares C1 only.
        auto const ctOther = elGamalEncrypt(m, r, otherPk);
        BEAST_EXPECT(ctOther.c1 == ct.c1);
        BEAST_EXPECT(!(ctOther.c2 == ct.c2));
    }

    void
    testHomomorphism()
    {
        testcase("ElGamal homomorphism");

        auto const sk = Scalar::fromUint64(0xABCDEF);
        auto const pk = mulGenerator(sk);

        std::uint64_t const m1 = 700;
        std::uint64_t const m2 = 300;
        std::uint64_t const r1 = 0x1111;
        std::uint64_t const r2 = 0x0222;

        auto const c1 = elGamalEncrypt(Scalar::fromUint64(m1), Scalar::fromUint64(r1), pk);
        auto const c2 = elGamalEncrypt(Scalar::fromUint64(m2), Scalar::fromUint64(r2), pk);

        auto const sum = c1 + c2;
        BEAST_EXPECT(verifyElGamalEncryption(
            sum, Scalar::fromUint64(m1 + m2), Scalar::fromUint64(r1 + r2), pk));

        auto const diff = c1 - c2;
        BEAST_EXPECT(verifyElGamalEncryption(
            diff, Scalar::fromUint64(m1 - m2), Scalar::fromUint64(r1 - r2), pk));
        BEAST_EXPECT(diff.c2 - sk * diff.c1 == mulGenerator(Scalar::fromUint64(m1 - m2)));

        BEAST_EXPECT(sum - c2 == c1);
        BEAST_EXPECT(diff + c2 == c1);

        // Adding an encryption of zero re-randomizes without changing m.
        auto const rerandomized = c1 + elGamalEncrypt(Scalar{}, Scalar::fromUint64(5), pk);
        BEAST_EXPECT(!(rerandomized == c1));
        BEAST_EXPECT(
            rerandomized.c2 - sk * rerandomized.c1 == mulGenerator(Scalar::fromUint64(m1)));

        // Subtracting a ciphertext from itself yields the identity, which is
        // not a serializable ciphertext.
        BEAST_EXPECT((c1 - c1).c1.isInfinity());
        BEAST_EXPECT((c1 - c1).c2.isInfinity());
        BEAST_EXPECT(!(c1 - c1).toBuffer());
    }

public:
    void
    run() override
    {
        testScalar();
        testPointEncoding();
        testPointArithmetic();
        testCiphertextEncoding();
        testEncryption();
        testHomomorphism();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialCrypto, protocol, xrpl);

}  // namespace xrpl::confidential
