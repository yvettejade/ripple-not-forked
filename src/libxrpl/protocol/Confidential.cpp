#include <xrpl/protocol/Confidential.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/protocol/detail/secp256k1.h>

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>

namespace xrpl {
namespace {

// #region agent log
inline void
agentDbg(char const* hyp, char const* loc, char const* msg, int v = 0)
{
    if (FILE* f = std::fopen("/opt/cursor/logs/debug.log", "a"))
    {
        std::fprintf(
            f,
            "{\"hypothesisId\":\"%s\",\"location\":\"%s\",\"message\":\"%s\",\"data\":{\"v\":%d},"
            "\"timestamp\":0}\n",
            hyp,
            loc,
            msg,
            v);
        std::fclose(f);
    }
}
// #endregion



uint256 const&
secp256k1Order()
{
    static uint256 const kN = [] {
        uint256 n;
        if (!n.parseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
            logicError("secp256k1Order: invalid hex");
        return n;
    }();
    return kN;
}

void
subtractBE(uint256& x, uint256 const& y)
{
    unsigned int borrow = 0;
    for (int i = 31; i >= 0; --i)
    {
        unsigned int const lhs = x.data()[i];
        unsigned int const rhs = y.data()[i] + borrow;
        if (lhs < rhs)
        {
            x.data()[i] = static_cast<unsigned char>(lhs + 256u - rhs);
            borrow = 1;
        }
        else
        {
            x.data()[i] = static_cast<unsigned char>(lhs - rhs);
            borrow = 0;
        }
    }
}

uint256
reduceModN(uint256 x)
{
    auto const& n = secp256k1Order();
    if (x >= n)
        subtractBE(x, n);
    if (!x)
        x = uint256{std::uint64_t{1}};
    return x;
}

void
u64ToScalar(std::uint64_t v, unsigned char out[32])
{
    std::memset(out, 0, 32);
    for (int i = 0; i < 8; ++i)
        out[31 - i] = static_cast<unsigned char>(v >> (8 * i));
}

[[nodiscard]] bool
parsePoint(Slice const& bytes, secp256k1_pubkey& out)
{
    return bytes.size() == kConfidentialPubKeyLength &&
        secp256k1_ec_pubkey_parse(secp256k1Context(), &out, bytes.data(), bytes.size()) == 1;
}

[[nodiscard]] bool
serializePoint(secp256k1_pubkey const& pk, unsigned char out[kConfidentialPubKeyLength])
{
    std::size_t len = kConfidentialPubKeyLength;
    return secp256k1_ec_pubkey_serialize(
               secp256k1Context(), out, &len, &pk, SECP256K1_EC_COMPRESSED) == 1 &&
        len == kConfidentialPubKeyLength;
}

[[nodiscard]] std::optional<secp256k1_pubkey>
createPoint(unsigned char const scalar[32])
{
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &pk, scalar) != 1)
        return std::nullopt;
    return pk;
}

[[nodiscard]] std::optional<secp256k1_pubkey>
combine(secp256k1_pubkey const& a, secp256k1_pubkey const& b)
{
    secp256k1_pubkey const* ins[2] = {&a, &b};
    secp256k1_pubkey out;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &out, ins, 2) != 1)
        return std::nullopt;
    return out;
}

/** NUMS stand-in for the EC identity; libsecp256k1 cannot serialize O. */
[[nodiscard]] secp256k1_pubkey const&
identityPoint()
{
    static secp256k1_pubkey const kId = [] {
        static constexpr char const kDomain[] = "XLS-0096/ElGamal/Identity";
        sha512_half_hasher h;
        h(kDomain, sizeof(kDomain) - 1);
        uint256 x = static_cast<uint256>(h);
        for (std::uint32_t t = 0; t < (1u << 20); ++t)
        {
            unsigned char enc[kConfidentialPubKeyLength];
            enc[0] = 0x02;
            std::memcpy(enc + 1, x.data(), 32);
            secp256k1_pubkey pk;
            if (secp256k1_ec_pubkey_parse(secp256k1Context(), &pk, enc, sizeof(enc)) == 1)
                return pk;
            enc[0] = 0x03;
            if (secp256k1_ec_pubkey_parse(secp256k1Context(), &pk, enc, sizeof(enc)) == 1)
                return pk;
            ++x;
        }
        logicError("identityPoint: hash-to-curve failed");
        return secp256k1_pubkey{};
    }();
    return kId;
}

[[nodiscard]] bool
isIdentityPoint(secp256k1_pubkey const& pk)
{
    unsigned char a[kConfidentialPubKeyLength];
    unsigned char b[kConfidentialPubKeyLength];
    if (!serializePoint(pk, a) || !serializePoint(identityPoint(), b))
        return false;
    return std::memcmp(a, b, sizeof(a)) == 0;
}

/** Point add that maps infinity to the identity sentinel and treats the sentinel as O. */
[[nodiscard]] std::optional<secp256k1_pubkey>
combineAllowIdentity(secp256k1_pubkey const& a, secp256k1_pubkey const& b)
{
    bool const aId = isIdentityPoint(a);
    bool const bId = isIdentityPoint(b);
    if (aId && bId)
        return identityPoint();
    if (aId)
        return b;
    if (bId)
        return a;
    if (auto out = combine(a, b))
        return out;
    return identityPoint();
}

[[nodiscard]] std::optional<Buffer>
serializeCiphertext(secp256k1_pubkey const& r, secp256k1_pubkey const& s)
{
    Buffer out(kConfidentialCiphertextLength);
    if (!serializePoint(r, out.data()) ||
        !serializePoint(s, out.data() + kConfidentialPubKeyLength))
        return std::nullopt;
    return out;
}

[[nodiscard]] bool
parseCiphertext(Slice const& ct, secp256k1_pubkey& r, secp256k1_pubkey& s)
{
    if (ct.size() != kConfidentialCiphertextLength)
        return false;
    return parsePoint(Slice(ct.data(), kConfidentialPubKeyLength), r) &&
        parsePoint(Slice(ct.data() + kConfidentialPubKeyLength, kConfidentialPubKeyLength), s);
}

[[nodiscard]] std::optional<secp256k1_pubkey>
tweakMul(secp256k1_pubkey pk, unsigned char const scalar[32])
{
    if (secp256k1_ec_pubkey_tweak_mul(secp256k1Context(), &pk, scalar) != 1)
        return std::nullopt;
    return pk;
}

}  // namespace

bool
isConfidentialPubKey(Slice const& key)
{
    secp256k1_pubkey pk;
    return parsePoint(key, pk);
}

bool
isConfidentialCiphertext(Slice const& ct)
{
    secp256k1_pubkey r;
    secp256k1_pubkey s;
    return parseCiphertext(ct, r, s);
}

bool
isConfidentialScalar(uint256 const& scalar)
{
    return secp256k1_ec_seckey_verify(secp256k1Context(), scalar.data()) == 1;
}

std::optional<Buffer>
elgamalEncrypt(Slice const& pkBytes, std::uint64_t m, uint256 const& r)
{
    secp256k1_pubkey pk;
    if (!parsePoint(pkBytes, pk) || !isConfidentialScalar(r))
        return std::nullopt;
    if (m > kMaxMpTokenAmount)
        return std::nullopt;

    auto const R = createPoint(r.data());
    if (!R)
        return std::nullopt;

    auto const rPk = tweakMul(pk, r.data());
    if (!rPk)
        return std::nullopt;

    if (m == 0)
        return serializeCiphertext(*R, *rPk);

    unsigned char mScalar[32];
    u64ToScalar(m, mScalar);
    auto const mG = createPoint(mScalar);
    if (!mG)
        return std::nullopt;
    auto const S = combine(*mG, *rPk);
    if (!S)
        return std::nullopt;
    return serializeCiphertext(*R, *S);
}

std::optional<Buffer>
elgamalAdd(Slice const& a, Slice const& b)
{
    secp256k1_pubkey ra;
    secp256k1_pubkey sa;
    secp256k1_pubkey rb;
    secp256k1_pubkey sb;
    if (!parseCiphertext(a, ra, sa) || !parseCiphertext(b, rb, sb))
        return std::nullopt;
    auto const r = combineAllowIdentity(ra, rb);
    auto const s = combineAllowIdentity(sa, sb);
    if (!r || !s)
        return std::nullopt;
    return serializeCiphertext(*r, *s);
}

std::optional<Buffer>
elgamalSub(Slice const& a, Slice const& b)
{
    secp256k1_pubkey ra;
    secp256k1_pubkey sa;
    secp256k1_pubkey rb;
    secp256k1_pubkey sb;
    if (!parseCiphertext(a, ra, sa) || !parseCiphertext(b, rb, sb))
        return std::nullopt;
    if (isIdentityPoint(rb))
    {
        // -O = O; leave rb as identity sentinel.
    }
    else if (secp256k1_ec_pubkey_negate(secp256k1Context(), &rb) != 1)
    {
        return std::nullopt;
    }
    if (isIdentityPoint(sb))
    {
        // -O = O
    }
    else if (secp256k1_ec_pubkey_negate(secp256k1Context(), &sb) != 1)
    {
        return std::nullopt;
    }
    auto const r = combineAllowIdentity(ra, rb);
    auto const s = combineAllowIdentity(sa, sb);
    // #region agent log
    {
        int const same = (a.size() == b.size() &&
                          std::memcmp(a.data(), b.data(), a.size()) == 0)
            ? 1
            : 0;
        agentDbg(
            "A",
            "Confidential.cpp:elgamalSub",
            "combine_result",
            (r ? 1 : 0) | ((s ? 1 : 0) << 1) | (same << 2) |
                ((r && isIdentityPoint(*r) && s && isIdentityPoint(*s)) ? 8 : 0));
    }
    // #endregion
    if (!r || !s)
        return std::nullopt;
    return serializeCiphertext(*r, *s);
}

std::optional<Buffer>
encZero(AccountID const& account, AccountID const& issuer, MPTID const& mptId, Slice const& pk)
{
    sha512_half_hasher h;
    static constexpr char const kDomain[] = "EncZero";
    h(kDomain, sizeof(kDomain) - 1);
    h(account.data(), account.size());
    h(issuer.data(), issuer.size());
    h(mptId.data(), mptId.size());
    auto r = reduceModN(static_cast<uint256>(h));
    return elgamalEncrypt(pk, 0, r);
}

bool
elgamalMatches(Slice const& ciphertext, Slice const& pk, std::uint64_t m, uint256 const& r)
{
    auto const expected = elgamalEncrypt(pk, m, r);
    if (!expected || expected->size() != ciphertext.size())
        return false;
    return std::memcmp(expected->data(), ciphertext.data(), ciphertext.size()) == 0;
}

Buffer
convertSchnorrTranscript(AccountID const& account, MPTID const& mptId)
{
    static constexpr char const kDomain[] = "XLS-0096/ConfidentialMPTConvert/SchnorrPoK";
    Buffer out(sizeof(kDomain) - 1 + account.size() + mptId.size());
    auto* p = out.data();
    std::memcpy(p, kDomain, sizeof(kDomain) - 1);
    p += sizeof(kDomain) - 1;
    std::memcpy(p, account.data(), account.size());
    p += account.size();
    std::memcpy(p, mptId.data(), mptId.size());
    return out;
}

namespace {

uint256
schnorrChallenge(secp256k1_pubkey const& R, Slice const& pk, Slice const& transcript)
{
    unsigned char rBytes[kConfidentialPubKeyLength];
    if (!serializePoint(R, rBytes))
        logicError("schnorrChallenge: serialize R");
    sha512_half_hasher h;
    h(rBytes, sizeof(rBytes));
    h(pk.data(), pk.size());
    h(transcript.data(), transcript.size());
    return reduceModN(static_cast<uint256>(h));
}

}  // namespace

std::optional<Buffer>
schnorrProve(Slice const& pk, Slice const& sk, Slice const& transcript)
{
    if (!isConfidentialPubKey(pk) || sk.size() != 32 ||
        secp256k1_ec_seckey_verify(secp256k1Context(), sk.data()) != 1)
        return std::nullopt;

    secp256k1_pubkey parsedPk;
    if (!parsePoint(pk, parsedPk))
        return std::nullopt;
    auto const expectedPk = createPoint(sk.data());
    if (!expectedPk)
        return std::nullopt;
    unsigned char expectedBytes[kConfidentialPubKeyLength];
    unsigned char pkBytes[kConfidentialPubKeyLength];
    if (!serializePoint(*expectedPk, expectedBytes) || !serializePoint(parsedPk, pkBytes))
        return std::nullopt;
    if (std::memcmp(expectedBytes, pkBytes, sizeof(pkBytes)) != 0)
        return std::nullopt;

    std::array<unsigned char, 32> k{};
    auto& rng = cryptoPrng();
    do
    {
        rng(k.data(), k.size());
    } while (secp256k1_ec_seckey_verify(secp256k1Context(), k.data()) != 1);

    auto const R = createPoint(k.data());
    if (!R)
        return std::nullopt;

    auto const c = schnorrChallenge(*R, pk, transcript);
    std::array<unsigned char, 32> s{};
    std::memcpy(s.data(), sk.data(), 32);
    if (secp256k1_ec_seckey_tweak_mul(secp256k1Context(), s.data(), c.data()) != 1)
        return std::nullopt;
    if (secp256k1_ec_seckey_tweak_add(secp256k1Context(), s.data(), k.data()) != 1)
        return std::nullopt;

    Buffer proof(kConfidentialSchnorrProofLength);
    std::memcpy(proof.data(), c.data(), 32);
    std::memcpy(proof.data() + 32, s.data(), 32);
    return proof;
}

bool
schnorrVerify(Slice const& pk, Slice const& proof, Slice const& transcript)
{
    if (proof.size() != kConfidentialSchnorrProofLength)
        return false;
    secp256k1_pubkey parsedPk;
    if (!parsePoint(pk, parsedPk))
        return false;

    uint256 c;
    uint256 s;
    std::memcpy(c.data(), proof.data(), 32);
    std::memcpy(s.data(), proof.data() + 32, 32);
    if (!isConfidentialScalar(c) || !isConfidentialScalar(s))
        return false;

    auto const sG = createPoint(s.data());
    auto const cPk = tweakMul(parsedPk, c.data());
    if (!sG || !cPk)
        return false;
    secp256k1_pubkey cPkNeg = *cPk;
    if (secp256k1_ec_pubkey_negate(secp256k1Context(), &cPkNeg) != 1)
        return false;
    auto const R = combine(*sG, cPkNeg);
    if (!R)
        return false;

    auto const cCheck = schnorrChallenge(*R, pk, transcript);
    return c == cCheck;
}

}  // namespace xrpl
