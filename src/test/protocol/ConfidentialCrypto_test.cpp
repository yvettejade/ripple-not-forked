#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/UintTypes.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

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
    static constexpr char const* kOrderMinusFive =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413C";
    // Field prime p; an x coordinate equal to p is not canonical.
    static constexpr char const* kFieldPrime =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    // BIP-340 test vector secret key and its compressed public key.
    static constexpr char const* kBip340Secret =
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
    static constexpr char const* kBip340Public =
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
    // P = 987654321·G and -P.
    static constexpr char const* kP =
        "035AD2703F5B4F4B9DEA4C28FA30D86D3781D28E09DD51AAE1208DE80BB6155BEE";
    static constexpr char const* kMinusP =
        "025AD2703F5B4F4B9DEA4C28FA30D86D3781D28E09DD51AAE1208DE80BB6155BEE";

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
        BEAST_EXPECT(!Scalar::fromBytes(makeSlice(
                                            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                                                "BAAEDCE6AF48A03BBFD25E8CD0364142")))
                          .has_value());
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
        // Odd-y points round-trip through parse and serialize.
        BEAST_EXPECT(toHex(point(kMinusG)) == kMinusG);
        BEAST_EXPECT(toHex(point(kP)) == kP);

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
        BEAST_EXPECT(!isValidPoint(makeSlice(hex(std::string("02") + kFieldPrime))));
        BEAST_EXPECT(!isValidPoint(makeSlice(hex(std::string("03") + kFieldPrime))));
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

        BEAST_EXPECT(g == mulGenerator(Scalar::fromUint64(1)));
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
        BEAST_EXPECT(orderMinusOne && toHex(*orderMinusOne * point(kP)) == kMinusP);
        BEAST_EXPECT(-(-g) == g);
        BEAST_EXPECT(-point(kP) == point(kMinusP));

        // A full-width scalar.
        auto const bip340 = Scalar::fromBytes(makeSlice(hex(kBip340Secret)));
        BEAST_EXPECT(bip340 && toHex(mulGenerator(*bip340)) == kBip340Public);
        BEAST_EXPECT(bip340 && toHex(*bip340 * g) == kBip340Public);

        // Identity behaviour, including sums that cancel.
        Point const o;
        BEAST_EXPECT(g + o == g);
        BEAST_EXPECT(o + g == g);
        BEAST_EXPECT((o + o).isInfinity());
        BEAST_EXPECT((-o).isInfinity());
        BEAST_EXPECT((g - g).isInfinity());
        BEAST_EXPECT((g + (-g)).isInfinity());
        BEAST_EXPECT((g + (-g)) + g == g);
        BEAST_EXPECT(o - g == -g);
        BEAST_EXPECT((Scalar{} * g).isInfinity());
        BEAST_EXPECT((two * o).isInfinity());
        BEAST_EXPECT(mulGenerator(Scalar{}).isInfinity());
        BEAST_EXPECT(o == Point{});
        BEAST_EXPECT(!(o == g));
        BEAST_EXPECT(!(g == o));
        BEAST_EXPECT(!(g == -g));

        // The constant-time multiplication agrees with the public one.
        BEAST_EXPECT(mulSecret(two, g) == two * g);
        BEAST_EXPECT(orderMinusOne && mulSecret(*orderMinusOne, point(kP)) == point(kMinusP));
        for (int i = 0; i < 4; ++i)
        {
            auto const k = Scalar::random();
            auto const q = mulGenerator(Scalar::random());
            BEAST_EXPECT(mulSecret(k, q) == k * q);
            BEAST_EXPECT(mulSecret(k, g) == mulGenerator(k));
        }
        BEAST_EXPECT(mulSecret(Scalar{}, g).isInfinity());
        BEAST_EXPECT(mulSecret(two, o).isInfinity());

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

        // In-memory ciphertexts with a component at infinity never verify,
        // even when they match the computed encryption.
        BEAST_EXPECT(!verifyElGamalEncryption(
            ElGamalCiphertext{.c1 = Point{}, .c2 = mulGenerator(m)}, m, Scalar{}, pk));
        BEAST_EXPECT(!verifyElGamalEncryption(ElGamalCiphertext{}, Scalar{}, Scalar{}, pk));
        {
            // m = n - 1 and r = 1 under pk = G cancel in C2.
            auto const orderMinusOne = Scalar::fromBytes(makeSlice(hex(kOrderMinusOne)));
            if (BEAST_EXPECT(orderMinusOne))
            {
                auto const one = Scalar::fromUint64(1);
                auto const g = Point::generator();
                auto const cancelled = elGamalEncrypt(*orderMinusOne, one, g);
                BEAST_EXPECT(cancelled.c2.isInfinity());
                BEAST_EXPECT(!verifyElGamalEncryption(cancelled, *orderMinusOne, one, g));
            }
        }

        // Encrypting under the identity is a caller error.
        bool threw = false;
        try
        {
            (void)elGamalEncrypt(m, r, Point{});
        }
        catch (std::invalid_argument const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);

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

        // Blinding factors summing to n cancel C1 while C2 still carries
        // m1 + m2; the result cannot be stored.
        {
            auto const minusFive = Scalar::fromBytes(makeSlice(hex(kOrderMinusFive)));
            if (BEAST_EXPECT(minusFive))
            {
                auto const partial =
                    elGamalEncrypt(Scalar::fromUint64(m1), Scalar::fromUint64(5), pk) +
                    elGamalEncrypt(Scalar::fromUint64(m2), *minusFive, pk);
                BEAST_EXPECT(partial.c1.isInfinity());
                BEAST_EXPECT(partial.c2 == mulGenerator(Scalar::fromUint64(m1 + m2)));
                BEAST_EXPECT(!partial.toBuffer());
            }
        }

        // Subtracting a ciphertext from itself yields the identity, which is
        // not a serializable ciphertext.
        BEAST_EXPECT((c1 - c1).c1.isInfinity());
        BEAST_EXPECT((c1 - c1).c2.isInfinity());
        BEAST_EXPECT(!(c1 - c1).toBuffer());
    }

    void
    testScalarArithmetic()
    {
        testcase("Scalar arithmetic");

        auto const s = [](std::uint64_t v) { return Scalar::fromUint64(v); };
        auto const orderMinusOne = *Scalar::fromBytes(makeSlice(hex(kOrderMinusOne)));
        auto const one = s(1);

        BEAST_EXPECT(s(5) + s(7) == s(12));
        BEAST_EXPECT(s(7) - s(5) == s(2));
        BEAST_EXPECT(s(6) * s(7) == s(42));
        BEAST_EXPECT(Scalar{} + s(9) == s(9));
        BEAST_EXPECT(s(9) + Scalar{} == s(9));
        BEAST_EXPECT((s(9) * Scalar{}).isZero());
        BEAST_EXPECT((Scalar{} * s(9)).isZero());
        BEAST_EXPECT((-Scalar{}).isZero());
        BEAST_EXPECT((s(9) - s(9)).isZero());

        // Wrap-around modulo n.
        BEAST_EXPECT(-one == orderMinusOne);
        BEAST_EXPECT(-orderMinusOne == one);
        BEAST_EXPECT((orderMinusOne + one).isZero());
        BEAST_EXPECT(orderMinusOne + s(2) == one);
        BEAST_EXPECT(orderMinusOne * orderMinusOne == one);
        BEAST_EXPECT(s(3) - s(5) == -s(2));

        // Inverses.
        BEAST_EXPECT(one.inverse() == one);
        BEAST_EXPECT(s(2).inverse() * s(2) == one);
        BEAST_EXPECT(orderMinusOne.inverse() == orderMinusOne);
        auto const bip340 = *Scalar::fromBytes(makeSlice(hex(kBip340Secret)));
        BEAST_EXPECT(bip340.inverse() * bip340 == one);
        bool threw = false;
        try
        {
            (void)Scalar{}.inverse();
        }
        catch (std::domain_error const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);

        // Field laws on random values, and consistency with the group.
        for (int i = 0; i < 8; ++i)
        {
            auto const a = Scalar::random();
            auto const b = Scalar::random();
            auto const c = Scalar::random();
            BEAST_EXPECT(a * (b + c) == a * b + a * c);
            BEAST_EXPECT((a * b) * c == a * (b * c));
            BEAST_EXPECT(a + b == b + a);
            BEAST_EXPECT(a - b + b == a);
            BEAST_EXPECT(a * a.inverse() == one);
            BEAST_EXPECT(mulGenerator(a + b) == mulGenerator(a) + mulGenerator(b));
            BEAST_EXPECT(mulGenerator(a * b) == a * mulGenerator(b));
            BEAST_EXPECT(mulGenerator(-a) == -mulGenerator(a));
        }
    }

    void
    testDigestReduction()
    {
        testcase("Digest reduction");

        auto const digest = [](std::string const& h) {
            std::array<std::uint8_t, kScalarLength> out{};
            auto const b = hex(h);
            std::copy(b.begin(), b.end(), out.begin());
            return out;
        };

        BEAST_EXPECT(Scalar::fromDigest(digest(std::string(64, '0'))).isZero());
        BEAST_EXPECT(
            Scalar::fromDigest(digest(std::string(62, '0') + "2A")) == Scalar::fromUint64(42));
        BEAST_EXPECT(strHex(Scalar::fromDigest(digest(kOrderMinusOne)).bytes()) == kOrderMinusOne);
        BEAST_EXPECT(Scalar::fromDigest(digest(kOrder)).isZero());
        BEAST_EXPECT(
            Scalar::fromDigest(
                digest("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364146")) ==
            Scalar::fromUint64(5));
        // Reductions that borrow across bytes.
        BEAST_EXPECT(
            Scalar::fromDigest(
                digest("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364200")) ==
            Scalar::fromUint64(0xBF));
        BEAST_EXPECT(
            strHex(
                Scalar::fromDigest(
                    digest("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000"))
                    .bytes()) ==
            "000000000000000000000000000000004551231950B75FC4402DA1732FC9BEBF");
        // 2^256 - 1 - n
        BEAST_EXPECT(
            strHex(Scalar::fromDigest(digest(std::string(64, 'F'))).bytes()) ==
            "000000000000000000000000000000014551231950B75FC4402DA1732FC9BEBE");
    }

    void
    testRandom()
    {
        testcase("Random scalars");

        std::set<std::string> seen;
        for (int i = 0; i < 32; ++i)
        {
            auto const r = Scalar::random();
            BEAST_EXPECT(!r.isZero());
            BEAST_EXPECT(Scalar::fromBytes(makeSlice(r.bytes())) == r);
            BEAST_EXPECT(seen.insert(strHex(r.bytes())).second);
        }
    }

    void
    testGenerators()
    {
        testcase("Generators");

        // Reference values from an independent Python implementation of the
        // try-and-increment construction.
        BEAST_EXPECT(
            toHex(pedersenGenerator()) ==
            "0216337C9C8E1F92C51ADCDE0562CA57FE910B2D18EF442E16E85C62E9DE5148BE");
        BEAST_EXPECT(
            toHex(innerProductGenerator()) ==
            "029A3739ACCE6B1AE4E1C2297B597748A29200B74F205DD33CFF84BA4AEB84B640");

        auto const g = bulletproofGeneratorsG();
        auto const h = bulletproofGeneratorsH();
        if (!BEAST_EXPECT(g.size() == kMaxBulletproofBits && h.size() == kMaxBulletproofBits))
            return;
        BEAST_EXPECT(
            toHex(g[0]) == "02CEA2A2FD25B8E3A768EC4BFBA3962EB7D7AD38EC74AC77B3F1C611809C56BCBF");
        BEAST_EXPECT(
            toHex(g[1]) == "02CEB997DD16C3AB7EA520E0787500FBB9AFD25FCE8462AC524D5B51BFBA82E984");
        BEAST_EXPECT(
            toHex(g[127]) == "02D62B591366445527C27908697C9102526A5BE1E36FCA678572F54F894173AAD6");
        BEAST_EXPECT(
            toHex(h[0]) == "02C9A96A4011D71B5D7219C43F7B3B2432623B9277E4C2753CAAC95853685E37A0");
        BEAST_EXPECT(
            toHex(h[1]) == "029EBE592D38ED859D654311780BE8AD7FE5321DD8D235C107F41F18367C73E03F");
        BEAST_EXPECT(
            toHex(h[127]) == "028BB8AB58C4C58D25941E6D554B88390FFF3156003C5537F1C55180C70C2728CF");

        // All generators are distinct from each other and from G.
        std::set<std::string> all{toHex(Point::generator()), toHex(pedersenGenerator())};
        all.insert(toHex(innerProductGenerator()));
        for (std::size_t i = 0; i < kMaxBulletproofBits; ++i)
        {
            all.insert(toHex(g[i]));
            all.insert(toHex(h[i]));
        }
        BEAST_EXPECT(all.size() == 3 + 2 * kMaxBulletproofBits);

        // Every generator, pinned as SHA-256(G_0 || ... || G_127 || H_0 || ... || H_127).
        {
            Blob all;
            for (auto const* v : {&g, &h})
            {
                for (auto const& p : *v)
                {
                    auto const b = *p.bytes();
                    all.insert(all.end(), b.begin(), b.end());
                }
            }
            BEAST_EXPECT(
                strHex(sha256({makeSlice(all)})) ==
                "B40DB32027E6F8A4C5855A72DCD6EF3ACCC856AC9538DA1C02CC881FE337D8B0");
        }

        // Deterministic, and the same object on every call.
        BEAST_EXPECT(&pedersenGenerator() == &pedersenGenerator());
        std::string const seed = "CMPT_PEDERSEN_H";
        BEAST_EXPECT(hashToCurve(makeSlice(seed)) == pedersenGenerator());
    }

    void
    testHashing()
    {
        testcase("Hashing");

        std::string const abc = "abc";
        BEAST_EXPECT(
            strHex(sha256({makeSlice(abc)})) ==
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        std::string const a = "a";
        std::string const bc = "bc";
        BEAST_EXPECT(sha256({makeSlice(a), makeSlice(bc)}) == sha256({makeSlice(abc)}));
        BEAST_EXPECT(
            strHex(sha256({})) ==
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    }

    void
    testPedersen()
    {
        testcase("Pedersen commitments");

        auto const s = [](std::uint64_t v) { return Scalar::fromUint64(v); };
        BEAST_EXPECT(
            toHex(pedersenCommit(s(1000), s(77))) ==
            "029793491D041336F0945E1EA405C01BE02A74E2FBCE4E871801A95FEAB76F9294");
        BEAST_EXPECT(
            pedersenCommit(s(1000), s(77)) == mulGenerator(s(1000)) + s(77) * pedersenGenerator());
        BEAST_EXPECT(
            pedersenCommit(s(10), s(3)) + pedersenCommit(s(20), s(4)) ==
            pedersenCommit(s(30), s(7)));
        BEAST_EXPECT(
            pedersenCommit(s(30), s(7)) - pedersenCommit(s(20), s(4)) ==
            pedersenCommit(s(10), s(3)));
        BEAST_EXPECT(pedersenCommit(Scalar{}, Scalar{}).isInfinity());
        BEAST_EXPECT(pedersenCommit(Scalar{}, s(5)) == s(5) * pedersenGenerator());
    }

    void
    testMultiScalarMul()
    {
        testcase("Multi-scalar multiplication");

        auto const s = [](std::uint64_t v) { return Scalar::fromUint64(v); };
        std::vector<Scalar> scalars;
        std::vector<Point> points;
        Point expected;
        for (std::uint64_t i = 1; i <= 10; ++i)
        {
            scalars.push_back(Scalar::random());
            points.push_back(mulGenerator(s(i * 1000 + 7)));
            expected = expected + scalars.back() * points.back();
        }
        BEAST_EXPECT(multiScalarMul(scalars, points) == expected);

        // Zero scalars and identity points are skipped.
        scalars.push_back(Scalar{});
        points.push_back(Point::generator());
        scalars.push_back(s(3));
        points.push_back(Point{});
        BEAST_EXPECT(multiScalarMul(scalars, points) == expected);

        BEAST_EXPECT(multiScalarMul({}, {}).isInfinity());
        std::vector<Scalar> const zeros(3);
        std::vector<Point> const gs(3, Point::generator());
        BEAST_EXPECT(multiScalarMul(zeros, gs).isInfinity());

        // A sum that cancels is the identity.
        std::vector<Scalar> const cancel{s(5), -s(5)};
        std::vector<Point> const same{Point::generator(), Point::generator()};
        BEAST_EXPECT(multiScalarMul(cancel, same).isInfinity());

        bool threw = false;
        try
        {
            (void)multiScalarMul(cancel, gs);
        }
        catch (std::invalid_argument const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);
    }

    void
    testEncryptedZero()
    {
        testcase("Canonical encrypted zero");

        AccountID account;
        std::fill(account.begin(), account.end(), 0x11);
        AccountID issuer;
        std::fill(issuer.begin(), issuer.end(), 0x22);
        auto const issuance = makeMptID(7, issuer);
        auto const sk = Scalar::fromUint64(0xC0FFEE);
        auto const pk = mulGenerator(sk);

        auto const r = encryptedZeroRandomness(account, issuance);
        BEAST_EXPECT(
            strHex(r.bytes()) ==
            "BD18E7336467D6C7B1C1D7B59E1DE1529617156B973459442FBB3926DFF91745");

        auto const zero = encryptedZero(account, issuance, pk);
        auto const buf = zero.toBuffer();
        BEAST_EXPECT(
            buf &&
            strHex(*buf) ==
                "020EF52C67196B62F575759E655140A3EEA5592F73A6025D9995680D65FF12F4AB"
                "03F4E97150F4A483266C4663E2F244AD6DF2BEF0AD0A54E029CA02C7F970EF0F7C");
        BEAST_EXPECT(verifyElGamalEncryption(zero, Scalar{}, r, pk));
        BEAST_EXPECT((zero.c2 - sk * zero.c1).isInfinity());
        BEAST_EXPECT(encryptedZero(account, issuance, pk) == zero);

        // Distinct per account, per issuance, and per key.
        AccountID other = account;
        other.data()[0] = 0x12;
        BEAST_EXPECT(!(encryptedZero(other, issuance, pk) == zero));
        BEAST_EXPECT(!(encryptedZero(account, makeMptID(8, issuer), pk) == zero));
        auto const otherKey = encryptedZero(account, issuance, mulGenerator(Scalar::fromUint64(5)));
        BEAST_EXPECT(otherKey.c1 == zero.c1);
        BEAST_EXPECT(!(otherKey.c2 == zero.c2));
    }

    void
    testContextID()
    {
        testcase("Transaction context");

        AccountID account;
        std::fill(account.begin(), account.end(), 0x11);
        AccountID issuer;
        std::fill(issuer.begin(), issuer.end(), 0x22);
        AccountID party;
        std::fill(party.begin(), party.end(), 0x33);
        auto const issuance = makeMptID(7, issuer);

        auto const id =
            transactionContextID(0x58, account, issuance, 0x01020304, party, 0xA0B0C0D0);
        BEAST_EXPECT(
            to_string(id) == "EEC5F99B11BEEE197096BE09515B83A383DD3E4A01EBCEF3DF00EE4DB2B9D5D8");

        // Every input is bound.
        BEAST_EXPECT(
            transactionContextID(0x57, account, issuance, 0x01020304, party, 0xA0B0C0D0) != id);
        BEAST_EXPECT(
            transactionContextID(0x58, party, issuance, 0x01020304, party, 0xA0B0C0D0) != id);
        BEAST_EXPECT(
            transactionContextID(
                0x58, account, makeMptID(8, issuer), 0x01020304, party, 0xA0B0C0D0) != id);
        BEAST_EXPECT(
            transactionContextID(0x58, account, issuance, 0x01020305, party, 0xA0B0C0D0) != id);
        BEAST_EXPECT(
            transactionContextID(0x58, account, issuance, 0x01020304, account, 0xA0B0C0D0) != id);
        BEAST_EXPECT(
            transactionContextID(0x58, account, issuance, 0x01020304, party, 0xA0B0C0D1) != id);
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
        testScalarArithmetic();
        testDigestReduction();
        testRandom();
        testGenerators();
        testHashing();
        testPedersen();
        testMultiScalarMul();
        testEncryptedZero();
        testContextID();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialCrypto, protocol, xrpl);

}  // namespace xrpl::confidential
