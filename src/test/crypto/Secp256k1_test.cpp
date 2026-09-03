#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace xrpl {
namespace {

std::vector<std::uint8_t>
unhex(std::string const& hex)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + c - 'a';
        if (c >= 'A' && c <= 'F')
            return 10 + c - 'A';
        return -1;
    };

    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        int const hi = nib(hex[i]);
        int const lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::array<std::uint8_t, 33> const&
generatorBytes()
{
    static auto const kG = [] {
        auto const v = unhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        std::array<std::uint8_t, 33> a{};
        std::memcpy(a.data(), v.data(), 33);
        return a;
    }();
    return kG;
}

std::array<std::uint8_t, 33> const&
twoGBytes()
{
    static auto const k2G = [] {
        auto const v = unhex("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
        std::array<std::uint8_t, 33> a{};
        std::memcpy(a.data(), v.data(), 33);
        return a;
    }();
    return k2G;
}

std::array<std::uint8_t, 32>
scalarOne()
{
    std::array<std::uint8_t, 32> s{};
    s[31] = 0x01;
    return s;
}

std::array<std::uint8_t, 32>
scalarTwo()
{
    std::array<std::uint8_t, 32> s{};
    s[31] = 0x02;
    return s;
}

std::array<std::uint8_t, 32>
scalarN()
{
    auto const v = unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    std::array<std::uint8_t, 32> s{};
    std::memcpy(s.data(), v.data(), 32);
    return s;
}

}  // namespace

class Secp256k1_test : public beast::unit_test::Suite
{
public:
    void
    testPointParseSerialize()
    {
        testcase("Point parse/serialize");

        auto const g = Secp256k1Point::parse(makeSlice(generatorBytes()));
        BEAST_EXPECT(g);
        BEAST_EXPECT(g->serialize() == generatorBytes());

        std::array<std::uint8_t, 33> out{};
        g->serialize(out.data());
        BEAST_EXPECT(out == generatorBytes());
        BEAST_EXPECT(g->size() == 33);
        BEAST_EXPECT(g->slice().size() == 33);
        BEAST_EXPECT(std::memcmp(g->data(), generatorBytes().data(), 33) == 0);

        auto const g2 = Secp256k1Point::parse(g->slice());
        BEAST_EXPECT(g2);
        BEAST_EXPECT(*g2 == *g);
    }

    void
    testPointMalformed()
    {
        testcase("Point malformed encodings");

        BEAST_EXPECT(!Secp256k1Point::parse(Slice()));
        std::array<std::uint8_t, 32> shortBuf{};
        BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(shortBuf)));
        std::array<std::uint8_t, 34> longBuf{};
        BEAST_EXPECT(!Secp256k1Point::parse(Slice(longBuf.data(), longBuf.size())));

        {
            auto buf = generatorBytes();
            buf[0] = 0x04;
            BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(buf)));
            buf[0] = 0x00;
            BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(buf)));
            buf[0] = 0x01;
            BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(buf)));
        }

        {
            std::array<std::uint8_t, 33> z{};
            z[0] = 0x02;
            BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(z)));
        }

        {
            auto buf = generatorBytes();
            buf[1] ^= 0xff;
            buf[2] ^= 0xaa;
            buf[10] ^= 0x55;
            BEAST_EXPECT(!Secp256k1Point::parse(makeSlice(buf)));
        }
    }

    void
    testScalarParse()
    {
        testcase("Scalar parse");

        auto const one = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        BEAST_EXPECT(one);
        BEAST_EXPECT(one->serialize() == scalarOne());
        std::array<std::uint8_t, 32> out{};
        one->serialize(out.data());
        BEAST_EXPECT(out == scalarOne());
        BEAST_EXPECT(one->size() == 32);
        BEAST_EXPECT(one->slice().size() == 32);

        auto const two = Secp256k1Scalar::parse(makeSlice(scalarTwo()));
        BEAST_EXPECT(two);

        BEAST_EXPECT(!Secp256k1Scalar::parse(Slice()));
        std::array<std::uint8_t, 31> shortBuf{};
        BEAST_EXPECT(!Secp256k1Scalar::parse(makeSlice(shortBuf)));

        std::array<std::uint8_t, 32> zero{};
        BEAST_EXPECT(!Secp256k1Scalar::parse(makeSlice(zero)));

        BEAST_EXPECT(!Secp256k1Scalar::parse(makeSlice(scalarN())));

        {
            auto n1 = scalarN();
            n1[31] = static_cast<std::uint8_t>(n1[31] + 1);
            BEAST_EXPECT(!Secp256k1Scalar::parse(makeSlice(n1)));
        }

        {
            auto a = Secp256k1Scalar::parse(makeSlice(scalarOne()));
            BEAST_EXPECT(a);
            Secp256k1Scalar b(*a);
            BEAST_EXPECT(b.serialize() == scalarOne());
            Secp256k1Scalar c(std::move(b));
            BEAST_EXPECT(c.serialize() == scalarOne());
            Secp256k1Scalar d(*a);
            d = c;
            BEAST_EXPECT(d.serialize() == scalarOne());
            Secp256k1Scalar e(*a);
            e = std::move(c);
            BEAST_EXPECT(e.serialize() == scalarOne());
        }
    }

    void
    testGeneratorMultiply()
    {
        testcase("Generator multiply");

        auto const one = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        auto const two = Secp256k1Scalar::parse(makeSlice(scalarTwo()));
        BEAST_EXPECT(one && two);

        auto const g = generatorMultiply(*one);
        BEAST_EXPECT(g);
        BEAST_EXPECT(g->serialize() == generatorBytes());

        auto const twoG = generatorMultiply(*two);
        BEAST_EXPECT(twoG);
        BEAST_EXPECT(twoG->serialize() == twoGBytes());
    }

    void
    testPointMultiplyAddSubtract()
    {
        testcase("Point multiply/add/subtract");

        auto const one = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        auto const two = Secp256k1Scalar::parse(makeSlice(scalarTwo()));
        auto const g = Secp256k1Point::parse(makeSlice(generatorBytes()));
        BEAST_EXPECT(one && two && g);

        auto const twoG = pointMultiply(*g, *two);
        BEAST_EXPECT(twoG);
        BEAST_EXPECT(twoG->serialize() == twoGBytes());

        auto const sum = pointAdd(*g, *g);
        BEAST_EXPECT(sum);
        BEAST_EXPECT(sum->serialize() == twoGBytes());

        auto const back = pointSubtract(*sum, *g);
        BEAST_EXPECT(back);
        BEAST_EXPECT(*back == *g);

        BEAST_EXPECT(!pointSubtract(*g, *g));
        BEAST_EXPECT(!pointSubtract(*twoG, *twoG));

        auto const gAgain = pointSubtract(*twoG, *g);
        BEAST_EXPECT(gAgain);
        BEAST_EXPECT(!pointSubtract(*gAgain, *g));
    }

    void
    testElGamalParseSerialize()
    {
        testcase("ElGamal parse/serialize");

        auto const g = Secp256k1Point::parse(makeSlice(generatorBytes()));
        auto const twoG = Secp256k1Point::parse(makeSlice(twoGBytes()));
        BEAST_EXPECT(g && twoG);

        std::array<std::uint8_t, 66> raw{};
        g->serialize(raw.data());
        twoG->serialize(raw.data() + 33);

        auto const ct = ElGamalCiphertext::parse(makeSlice(raw));
        BEAST_EXPECT(ct);
        BEAST_EXPECT(ct->c1() == *g);
        BEAST_EXPECT(ct->c2() == *twoG);
        BEAST_EXPECT(ct->serialize() == raw);

        std::array<std::uint8_t, 66> out{};
        ct->serialize(out.data());
        BEAST_EXPECT(out == raw);

        BEAST_EXPECT(!ElGamalCiphertext::parse(Slice()));
        BEAST_EXPECT(!ElGamalCiphertext::parse(Slice(raw.data(), 65)));

        {
            auto bad = raw;
            bad[0] = 0x04;
            BEAST_EXPECT(!ElGamalCiphertext::parse(makeSlice(bad)));
        }
        {
            auto bad = raw;
            bad[33] = 0x00;
            BEAST_EXPECT(!ElGamalCiphertext::parse(makeSlice(bad)));
        }
    }

    void
    testElGamalEncryptHomomorphic()
    {
        testcase("ElGamal encrypt / homomorphic");

        auto const sk = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        auto const r1 = Secp256k1Scalar::parse(makeSlice(scalarTwo()));
        std::array<std::uint8_t, 32> r2bytes{};
        r2bytes[31] = 0x03;
        auto const r2 = Secp256k1Scalar::parse(makeSlice(r2bytes));
        BEAST_EXPECT(sk && r1 && r2);

        auto const pk = generatorMultiply(*sk);
        BEAST_EXPECT(pk);

        auto const ct0 = ElGamalCiphertext::encrypt(0, *pk, *r1);
        BEAST_EXPECT(ct0);
        BEAST_EXPECT(ct0->c1().serialize() == twoGBytes());
        BEAST_EXPECT(ct0->c2().serialize() == twoGBytes());

        auto const ct5 = ElGamalCiphertext::encrypt(5, *pk, *r1);
        BEAST_EXPECT(ct5);
        BEAST_EXPECT(ct5->serialize() != ct0->serialize());

        auto const ct5b = ElGamalCiphertext::parse(makeSlice(ct5->serialize()));
        BEAST_EXPECT(ct5b);
        BEAST_EXPECT(*ct5b == *ct5);

        auto const ct7 = ElGamalCiphertext::encrypt(7, *pk, *r2);
        BEAST_EXPECT(ct7);

        auto const sum = ct5->add(*ct7);
        BEAST_EXPECT(sum);
        auto const recovered = sum->subtract(*ct7);
        BEAST_EXPECT(recovered);
        BEAST_EXPECT(*recovered == *ct5);

        auto const sum0 = ct5->add(*ct0);
        BEAST_EXPECT(sum0);
        auto const back = sum0->subtract(*ct0);
        BEAST_EXPECT(back);
        BEAST_EXPECT(*back == *ct5);

        BEAST_EXPECT(!ct5->subtract(*ct5));
        BEAST_EXPECT(!ct0->subtract(*ct0));

        auto const double0 = ct0->add(*ct0);
        BEAST_EXPECT(double0);

        // Large amount still encrypts (uint64 fits in scalar field)
        auto const ctMax =
            ElGamalCiphertext::encrypt(std::numeric_limits<std::uint64_t>::max(), *pk, *r1);
        BEAST_EXPECT(ctMax);
        BEAST_EXPECT(ctMax->serialize() != ct5->serialize());
    }

    void
    testElGamalDeterministicKnown()
    {
        testcase("ElGamal deterministic known inputs");

        auto const sk = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        auto const r = Secp256k1Scalar::parse(makeSlice(scalarOne()));
        BEAST_EXPECT(sk && r);
        auto const pk = generatorMultiply(*sk);
        BEAST_EXPECT(pk);

        auto const ct = ElGamalCiphertext::encrypt(1, *pk, *r);
        BEAST_EXPECT(ct);
        BEAST_EXPECT(ct->c1().serialize() == generatorBytes());
        BEAST_EXPECT(ct->c2().serialize() == twoGBytes());

        auto const ctz = ElGamalCiphertext::encrypt(0, *pk, *r);
        BEAST_EXPECT(ctz);
        BEAST_EXPECT(ctz->c1().serialize() == generatorBytes());
        BEAST_EXPECT(ctz->c2().serialize() == generatorBytes());
    }

    void
    testInfinityViaAddNegatives()
    {
        testcase("Operations yielding infinity");

        auto const g = Secp256k1Point::parse(makeSlice(generatorBytes()));
        auto const twoG = Secp256k1Point::parse(makeSlice(twoGBytes()));
        BEAST_EXPECT(g && twoG);

        auto const negG = pointSubtract(*g, *twoG);
        BEAST_EXPECT(negG);
        BEAST_EXPECT(!pointAdd(*g, *negG));

        std::array<std::uint8_t, 66> a{};
        std::array<std::uint8_t, 66> b{};
        g->serialize(a.data());
        g->serialize(a.data() + 33);
        negG->serialize(b.data());
        g->serialize(b.data() + 33);

        auto const cta = ElGamalCiphertext::parse(makeSlice(a));
        auto const ctb = ElGamalCiphertext::parse(makeSlice(b));
        BEAST_EXPECT(cta && ctb);
        BEAST_EXPECT(!cta->add(*ctb));
        BEAST_EXPECT(!cta->subtract(*cta));

        // Subtract fails when only C2 cancels (distinct C1, identical C2)
        std::array<std::uint8_t, 66> left{};
        std::array<std::uint8_t, 66> right{};
        g->serialize(left.data());
        twoG->serialize(left.data() + 33);
        twoG->serialize(right.data());
        twoG->serialize(right.data() + 33);
        auto const ctl = ElGamalCiphertext::parse(makeSlice(left));
        auto const ctr = ElGamalCiphertext::parse(makeSlice(right));
        BEAST_EXPECT(ctl && ctr);
        BEAST_EXPECT(!ctl->subtract(*ctr));
    }

    void
    run() override
    {
        testPointParseSerialize();
        testPointMalformed();
        testScalarParse();
        testGeneratorMultiply();
        testPointMultiplyAddSubtract();
        testElGamalParseSerialize();
        testElGamalEncryptHomomorphic();
        testElGamalDeterministicKnown();
        testInfinityViaAddNegatives();
    }
};

BEAST_DEFINE_TESTSUITE(Secp256k1, crypto, xrpl);

}  // namespace xrpl
