#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/ConfidentialProofs.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace xrpl::confidential {

class ConfidentialProofs_test : public beast::unit_test::Suite
{
    // Proofs generated with fixed nonces by an independent Python
    // implementation of the Updated spec's equations.
    static constexpr char const* kPoK =
        "C9BCEA242B6A9490297FA84DE8E255EF294B8C4EC667A5F143CB8E7A06ACA6AE"
        "F117F348F5F170543BA759A37EBCA7B5BF3F76C7506CA72CEA7F4F446F0F479D";
    static constexpr char const* kSend3 =
        "993AFF9895FCE627530D940EF4A586EE7CA0427993A3939B8120F9142C0666EC"
        "A39D9B0278F8C2671B42969AE9A5C5A30CBA58762878E31574C235BDCEAC88A4"
        "77748776C56379A215AB203230C33D77E64C1658DB02D8DBAD3354627B45BE8B"
        "8E766C09E3E3099C6D0A5A6BA697168EBD8BA80B43524BDE536419DD9A459D0D"
        "8F58A28E86775EC28066F36F6DB7168FE1281AD106D0376E030A6542FA53B142"
        "17E41B17C113E5206ABBD33D3CF3D917FADC04782BCD5E9255D710E07F0DF3BA";
    static constexpr char const* kSend3Challenge =
        "993AFF9895FCE627530D940EF4A586EE7CA0427993A3939B8120F9142C0666EC";
    static constexpr char const* kSend4 =
        "B7ED6D614184D1C3AA4015910EEA8FD0CEF712B1FBA81B79E174A35F0D06763E"
        "9DDCD0F9FBB4D91442950FA8911072CD9503CC833262CB3F0BCF6E5D225FD91A"
        "E7269C0BDABF9D7ECE70531DD5A262F435540799A9A1886A0358715E1A537ACA"
        "777343E7EED364510A543EA24441CB38DEB1783F6AF9EC84AF98FC5AE912DEE5"
        "E22E54DB067F89CB5E2063BD66C2DD254DDB768A4219B6D9AA7341EE5C5952E7"
        "FB07B8CF2BBFEC4C8FB0109F91207A2FD3364BD747C0CEAB66ED2F1D123C1A61";
    static constexpr char const* kBalance =
        "52530865EF078BBD7889CC3FB57D1533DDE674AB22D412FE95CBC5382418ECE0"
        "9458CE2DB579DC1EDA45D8DCF09AD432B6F4BF3E4259478D9D31D4BBED557A80"
        "E26DF5DA3EAF2B84EE48C3B2264946EB8CCF549705CD31D3FE31D05CC5ED1A15"
        "FB1253A45FC7DC9627B6CB485BB6E12633099B841309632A74E246DA23D4BC67";
    static constexpr char const* kClawback =
        "2F0E7E28A7ECED03E6E2E30A6B1821CD8397D1199E0858B5BD701FB2370839AC"
        "43053B8DA76AFEC6326E4E69248AB91DBE6A0BCEB2EA0EB2010B16644B94B79C";
    static constexpr char const* kOrder =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

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

    static uint256
    context()
    {
        uint256 c;
        std::fill(c.begin(), c.end(), 0x42);
        return c;
    }

    // The fixture shared with the Python reference.
    struct Fixture
    {
        Scalar skA = s(0x1111);
        Point pa = mulGenerator(s(0x1111));
        Point pb = mulGenerator(s(0x2222));
        Point pi = mulGenerator(s(0x3333));
        Point pu = mulGenerator(s(0x4444));
        Scalar m = s(250);
        Scalar r = s(0x5555);
        Scalar b = s(1000);
        Scalar rho = s(0x6666);
        ElGamalCiphertext balance = elGamalEncrypt(s(1000), s(0x7777), mulGenerator(s(0x1111)));

        SendStatement
        send(bool auditor) const
        {
            SendStatement st;
            st.recipientKeys = {pa, pb, pi};
            if (auditor)
                st.recipientKeys.push_back(pu);
            st.senderKey = pa;
            st.c1 = mulGenerator(r);
            for (auto const& p : st.recipientKeys)
                st.c2.push_back(mulGenerator(m) + r * p);
            st.amountCommitment = pedersenCommit(m, r);
            st.balanceCommitment = pedersenCommit(b, rho);
            st.balance = balance;
            return st;
        }

        SendWitness
        witness() const
        {
            return {
                .amount = m,
                .randomness = r,
                .balance = b,
                .balanceBlinding = rho,
                .secretKey = skA};
        }

        BalanceStatement
        bal() const
        {
            return {.key = pa, .balance = balance, .balanceCommitment = pedersenCommit(b, rho)};
        }
    };

    // Every single-byte change to a valid proof must be rejected.
    template <class Verify>
    void
    expectTamperResistant(Blob const& proof, Verify const& verify)
    {
        for (std::size_t i = 0; i < proof.size(); ++i)
        {
            Blob bad = proof;
            bad[i] ^= 0x01;
            BEAST_EXPECTS(!verify(makeSlice(bad)), std::to_string(i));
        }
        BEAST_EXPECT(!verify(Slice(proof.data(), proof.size() - 1)));
        Blob longer = proof;
        longer.push_back(0);
        BEAST_EXPECT(!verify(makeSlice(longer)));
        BEAST_EXPECT(!verify(Slice{}));

        // Zero and non-canonical scalars are rejected in every position.
        for (std::size_t pos = 0; pos < proof.size(); pos += kScalarLength)
        {
            Blob zero = proof;
            std::fill(zero.begin() + pos, zero.begin() + pos + kScalarLength, 0);
            BEAST_EXPECT(!verify(makeSlice(zero)));
            Blob big = proof;
            auto const order = hex(kOrder);
            std::copy(order.begin(), order.end(), big.begin() + pos);
            BEAST_EXPECT(!verify(makeSlice(big)));
        }
    }

    template <class F>
    bool
    throws(F const& f)
    {
        try
        {
            f();
        }
        catch (std::runtime_error const&)
        {
            return true;
        }
        return false;
    }

    void
    testKnowledge()
    {
        testcase("Schnorr proof of knowledge");

        Fixture const f;
        auto const ctx = context();
        auto const vector = hex(kPoK);
        BEAST_EXPECT(vector.size() == kSchnorrProofLength);
        BEAST_EXPECT(verifyKnowledge(f.pa, makeSlice(vector), ctx));

        auto const proof = proveKnowledge(f.skA, ctx);
        BEAST_EXPECT(proof.size() == kSchnorrProofLength);
        BEAST_EXPECT(verifyKnowledge(f.pa, proof, ctx));

        uint256 otherCtx = ctx;
        otherCtx.data()[0] ^= 1;
        BEAST_EXPECT(!verifyKnowledge(f.pa, proof, otherCtx));
        BEAST_EXPECT(!verifyKnowledge(f.pb, proof, ctx));
        BEAST_EXPECT(!verifyKnowledge(Point{}, proof, ctx));

        expectTamperResistant(vector, [&](Slice p) { return verifyKnowledge(f.pa, p, ctx); });

        // A zero key has no encoding, so no proof can be produced for it.
        BEAST_EXPECT(throws([&] { (void)proveKnowledge(Scalar{}, ctx); }));
    }

    void
    testSend()
    {
        testcase("Send sigma proof");

        Fixture const f;
        auto const ctx = context();

        auto const v3 = hex(kSend3);
        auto const v4 = hex(kSend4);
        BEAST_EXPECT(v3.size() == kSendSigmaProofLength);
        auto const e = verifySend(f.send(false), makeSlice(v3), ctx);
        BEAST_EXPECT(e && strHex(e->bytes()) == kSend3Challenge);
        BEAST_EXPECT(verifySend(f.send(true), makeSlice(v4), ctx));
        // The recipient count is part of the statement.
        BEAST_EXPECT(!verifySend(f.send(true), makeSlice(v3), ctx));
        BEAST_EXPECT(!verifySend(f.send(false), makeSlice(v4), ctx));

        for (bool const auditor : {false, true})
        {
            auto const st = f.send(auditor);
            auto const proof = proveSend(st, f.witness(), ctx);
            BEAST_EXPECT(proof.size() == kSendSigmaProofLength);
            auto const challenge = verifySend(st, proof, ctx);
            BEAST_EXPECT(
                challenge &&
                std::equal(challenge->bytes().begin(), challenge->bytes().end(), proof.data()));

            uint256 otherCtx = ctx;
            otherCtx.data()[31] ^= 1;
            BEAST_EXPECT(!verifySend(st, proof, otherCtx));

            // Changing any statement element invalidates the proof.
            auto const other = mulGenerator(s(0xBAD));
            std::vector<std::function<void(SendStatement&)>> const mutations{
                [&](SendStatement& x) { x.recipientKeys[0] = other; },
                [&](SendStatement& x) { x.recipientKeys[1] = other; },
                [&](SendStatement& x) { x.recipientKeys.back() = other; },
                [&](SendStatement& x) { std::swap(x.recipientKeys[1], x.recipientKeys[2]); },
                [&](SendStatement& x) { x.senderKey = other; },
                [&](SendStatement& x) { x.c1 = other; },
                [&](SendStatement& x) { x.c2[0] = other; },
                [&](SendStatement& x) { x.c2.back() = other; },
                [&](SendStatement& x) { x.amountCommitment = other; },
                [&](SendStatement& x) { x.balanceCommitment = other; },
                [&](SendStatement& x) { x.balance.c1 = other; },
                [&](SendStatement& x) { x.balance.c2 = other; },
                [&](SendStatement& x) { x.c1 = Point{}; },
                [&](SendStatement& x) { x.c2.pop_back(); },
                [&](SendStatement& x) {
                    x.recipientKeys.clear();
                    x.c2.clear();
                },
            };
            for (std::size_t i = 0; i < mutations.size(); ++i)
            {
                auto bad = st;
                mutations[i](bad);
                BEAST_EXPECTS(!verifySend(bad, proof, ctx), std::to_string(i));
            }

            Blob const bytes(proof.data(), proof.data() + proof.size());
            expectTamperResistant(
                bytes, [&](Slice p) { return verifySend(st, p, ctx).has_value(); });
        }

        // An honest prover cannot prove a false statement.
        {
            auto const st = f.send(true);
            auto w = f.witness();
            w.amount = s(251);
            BEAST_EXPECT(!verifySend(st, proveSend(st, w, ctx), ctx));
            w = f.witness();
            w.balance = s(999);
            BEAST_EXPECT(!verifySend(st, proveSend(st, w, ctx), ctx));
            w = f.witness();
            w.secretKey = s(0x1112);
            BEAST_EXPECT(!verifySend(st, proveSend(st, w, ctx), ctx));

            // The destination ciphertext encrypts a different amount.
            auto bad = st;
            bad.c2[1] = mulGenerator(s(251)) + f.r * f.pb;
            BEAST_EXPECT(!verifySend(bad, proveSend(bad, f.witness(), ctx), ctx));
        }

        // A statement point at infinity cannot be proven.
        auto noC1 = f.send(false);
        noC1.c1 = Point{};
        BEAST_EXPECT(throws([&] { (void)proveSend(noC1, f.witness(), ctx); }));
    }

    void
    testBalance()
    {
        testcase("ConvertBack balance proof");

        Fixture const f;
        auto const ctx = context();
        auto const st = f.bal();

        auto const vector = hex(kBalance);
        BEAST_EXPECT(vector.size() == kConvertBackSigmaProofLength);
        BEAST_EXPECT(verifyBalance(st, makeSlice(vector), ctx));

        auto const proof = proveBalance(st, f.b, f.rho, f.skA, ctx);
        BEAST_EXPECT(proof.size() == kConvertBackSigmaProofLength);
        BEAST_EXPECT(verifyBalance(st, proof, ctx));

        uint256 otherCtx = ctx;
        otherCtx.data()[5] ^= 1;
        BEAST_EXPECT(!verifyBalance(st, proof, otherCtx));

        auto const other = mulGenerator(s(0xBAD));
        std::vector<std::function<void(BalanceStatement&)>> const mutations{
            [&](BalanceStatement& x) { x.key = other; },
            [&](BalanceStatement& x) { x.balance.c1 = other; },
            [&](BalanceStatement& x) { x.balance.c2 = other; },
            [&](BalanceStatement& x) { x.balanceCommitment = other; },
            [&](BalanceStatement& x) { x.balanceCommitment = Point{}; },
        };
        for (std::size_t i = 0; i < mutations.size(); ++i)
        {
            auto bad = st;
            mutations[i](bad);
            BEAST_EXPECTS(!verifyBalance(bad, proof, ctx), std::to_string(i));
        }

        expectTamperResistant(vector, [&](Slice p) { return verifyBalance(st, p, ctx); });

        BEAST_EXPECT(!verifyBalance(st, proveBalance(st, s(999), f.rho, f.skA, ctx), ctx));
        BEAST_EXPECT(!verifyBalance(st, proveBalance(st, f.b, s(1), f.skA, ctx), ctx));
        BEAST_EXPECT(!verifyBalance(st, proveBalance(st, f.b, f.rho, s(2), ctx), ctx));

        auto noKey = st;
        noKey.key = Point{};
        BEAST_EXPECT(throws([&] { (void)proveBalance(noKey, f.b, f.rho, f.skA, ctx); }));
    }

    void
    testClawback()
    {
        testcase("Clawback proof");

        Fixture const f;
        auto const ctx = context();
        auto const skI = s(0x3333);
        auto const mirror = elGamalEncrypt(s(1000), s(0x8888), f.pi);

        auto const vector = hex(kClawback);
        BEAST_EXPECT(vector.size() == kClawbackProofLength);
        BEAST_EXPECT(verifyClawback(f.pi, mirror, s(1000), makeSlice(vector), ctx));

        auto const proof = proveClawback(f.pi, mirror, s(1000), skI, ctx);
        BEAST_EXPECT(proof.size() == kClawbackProofLength);
        BEAST_EXPECT(verifyClawback(f.pi, mirror, s(1000), proof, ctx));

        // The revealed amount must be the encrypted one.
        BEAST_EXPECT(!verifyClawback(f.pi, mirror, s(999), proof, ctx));
        BEAST_EXPECT(!verifyClawback(f.pi, mirror, s(1001), proof, ctx));
        BEAST_EXPECT(!verifyClawback(
            f.pi, mirror, s(999), proveClawback(f.pi, mirror, s(999), skI, ctx), ctx));
        BEAST_EXPECT(!verifyClawback(f.pi, mirror, Scalar{}, proof, ctx));

        uint256 otherCtx = ctx;
        otherCtx.data()[9] ^= 1;
        BEAST_EXPECT(!verifyClawback(f.pi, mirror, s(1000), proof, otherCtx));
        BEAST_EXPECT(!verifyClawback(f.pb, mirror, s(1000), proof, ctx));
        auto other = mirror;
        other.c1 = mulGenerator(s(0xBAD));
        BEAST_EXPECT(!verifyClawback(f.pi, other, s(1000), proof, ctx));
        other = mirror;
        other.c2 = mulGenerator(s(0xBAD));
        BEAST_EXPECT(!verifyClawback(f.pi, other, s(1000), proof, ctx));

        // Only the issuer's secret key works.
        BEAST_EXPECT(!verifyClawback(
            f.pi, mirror, s(1000), proveClawback(f.pi, mirror, s(1000), s(0x3334), ctx), ctx));

        expectTamperResistant(
            vector, [&](Slice p) { return verifyClawback(f.pi, mirror, s(1000), p, ctx); });

        // m·G must be encodable, so the amount cannot be zero.
        BEAST_EXPECT(throws([&] { (void)proveClawback(f.pi, mirror, Scalar{}, skI, ctx); }));
    }

public:
    void
    run() override
    {
        testKnowledge();
        testSend();
        testBalance();
        testClawback();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialProofs, protocol, xrpl);

}  // namespace xrpl::confidential
