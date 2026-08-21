#include <xrpl/crypto/confidential/ElGamal.h>

#include <libxrpl/crypto/confidential/Detail.h>

#include <cstring>

namespace xrpl {
namespace crypto {
namespace confidential {

bool
parseCompressedPoint(Slice in, CompressedPoint& out) noexcept
{
    secp256k1_pubkey pk;
    return detail::parseStrictCompressed(in, pk, out);
}

bool
serializeCompressedPoint(CompressedPoint const& in, CompressedPoint& out) noexcept
{
    secp256k1_pubkey pk;
    if (!detail::parsePubkey(in, pk))
        return false;
    return detail::serializePubkey(pk, out);
}

bool
parseScalar(Slice in, Scalar& out) noexcept
{
    if (in.size() != kScalarBytes)
        return false;
    std::memcpy(out.data(), in.data(), kScalarBytes);
    return detail::scalarLessThanOrder(out);
}

bool
parseNonZeroScalar(Slice in, Scalar& out) noexcept
{
    if (!parseScalar(in, out))
        return false;
    return !scalarIsZero(out);
}

bool
scalarIsZero(Scalar const& k) noexcept
{
    for (auto b : k)
    {
        if (b != 0)
            return false;
    }
    return true;
}

bool
scalarFromUint64(std::uint64_t v, Scalar& out) noexcept
{
    out = {};
    for (int i = 7; i >= 0; --i)
    {
        out[24 + i] = static_cast<std::uint8_t>(v & 0xff);
        v >>= 8;
    }
    return detail::scalarLessThanOrder(out);
}

namespace {

bool
scalarBinOp(
    Scalar const& a,
    Scalar const& b,
    Scalar& out,
    int (*op)(BIGNUM*, BIGNUM const*, BIGNUM const*, BN_CTX*)) noexcept
{
    if (!detail::scalarLessThanOrder(a) || !detail::scalarLessThanOrder(b))
        return false;

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr)
        return false;

    BIGNUM* ba = BN_bin2bn(a.data(), 32, nullptr);
    BIGNUM* bb = BN_bin2bn(b.data(), 32, nullptr);
    BIGNUM* n = BN_bin2bn(detail::kCurveOrder.data(), 32, nullptr);
    BIGNUM* t = BN_new();
    BIGNUM* r = BN_new();

    bool ok = ba && bb && n && t && r && op(t, ba, bb, ctx) &&
        BN_nnmod(r, t, n, ctx) && detail::bnToScalar(r, out);

    BN_free(r);
    BN_free(t);
    BN_free(n);
    BN_free(bb);
    BN_free(ba);
    BN_CTX_free(ctx);
    return ok;
}

int
bnSubWrap(BIGNUM* r, BIGNUM const* a, BIGNUM const* b, BN_CTX*)
{
    return BN_sub(r, a, b);
}

int
bnAddWrap(BIGNUM* r, BIGNUM const* a, BIGNUM const* b, BN_CTX*)
{
    return BN_add(r, a, b);
}

int
bnMulWrap(BIGNUM* r, BIGNUM const* a, BIGNUM const* b, BN_CTX* ctx)
{
    return BN_mul(r, a, b, ctx);
}

}  // namespace

bool
scalarAdd(Scalar const& a, Scalar const& b, Scalar& out) noexcept
{
    return scalarBinOp(a, b, out, bnAddWrap);
}

bool
scalarSub(Scalar const& a, Scalar const& b, Scalar& out) noexcept
{
    return scalarBinOp(a, b, out, bnSubWrap);
}

bool
scalarMul(Scalar const& a, Scalar const& b, Scalar& out) noexcept
{
    return scalarBinOp(a, b, out, bnMulWrap);
}

bool
scalarNegate(Scalar const& a, Scalar& out) noexcept
{
    Scalar zero{};
    return scalarSub(zero, a, out);
}

bool
parseCiphertext(Slice in, Ciphertext& out) noexcept
{
    if (in.size() != kCiphertextBytes)
        return false;
    return parseCompressedPoint(Slice(in.data(), kCompressedPointBytes), out.R) &&
        parseCompressedPoint(
            Slice(in.data() + kCompressedPointBytes, kCompressedPointBytes),
            out.S);
}

bool
serializeCiphertext(Ciphertext const& in, CiphertextBlob& out) noexcept
{
    CompressedPoint r;
    CompressedPoint s;
    if (!serializeCompressedPoint(in.R, r) || !serializeCompressedPoint(in.S, s))
        return false;
    std::memcpy(out.data(), r.data(), kCompressedPointBytes);
    std::memcpy(out.data() + kCompressedPointBytes, s.data(), kCompressedPointBytes);
    return true;
}

namespace {

bool
ciphertextCombine(
    Ciphertext const& a,
    Ciphertext const& b,
    Ciphertext& out,
    bool subtract) noexcept
{
    secp256k1_pubkey aR;
    secp256k1_pubkey aS;
    secp256k1_pubkey bR;
    secp256k1_pubkey bS;
    if (!detail::parsePubkey(a.R, aR) || !detail::parsePubkey(a.S, aS) ||
        !detail::parsePubkey(b.R, bR) || !detail::parsePubkey(b.S, bS))
        return false;

    if (subtract)
    {
        secp256k1_ec_pubkey_negate(detail::context(), &bR);
        secp256k1_ec_pubkey_negate(detail::context(), &bS);
    }

    secp256k1_pubkey oR;
    secp256k1_pubkey oS;
    if (!detail::pointAdd(aR, bR, oR) || !detail::pointAdd(aS, bS, oS))
        return false;
    return detail::serializePubkey(oR, out.R) && detail::serializePubkey(oS, out.S);
}

}  // namespace

bool
ciphertextAdd(Ciphertext const& a, Ciphertext const& b, Ciphertext& out) noexcept
{
    return ciphertextCombine(a, b, out, false);
}

bool
ciphertextSub(Ciphertext const& a, Ciphertext const& b, Ciphertext& out) noexcept
{
    return ciphertextCombine(a, b, out, true);
}

bool
encrypt(
    CompressedPoint const& pk,
    std::uint64_t m,
    Scalar const& r,
    Ciphertext& out) noexcept
{
    Scalar rCanon;
    if (!parseNonZeroScalar(Slice(r.data(), r.size()), rCanon))
        return false;

    secp256k1_pubkey Y;
    if (!detail::parsePubkey(pk, Y))
        return false;

    // R = r·G
    secp256k1_pubkey R;
    if (!detail::pointMulG(rCanon, R))
        return false;

    // S = r·Pk
    secp256k1_pubkey S;
    if (!detail::pointMul(Y, rCanon, S))
        return false;

    // S += m·G when m != 0
    if (m != 0)
    {
        secp256k1_pubkey mG;
        if (!detail::pointMulGUint64(m, mG))
            return false;
        secp256k1_pubkey sum;
        if (!detail::pointAdd(S, mG, sum))
            return false;
        S = sum;
    }

    return detail::serializePubkey(R, out.R) && detail::serializePubkey(S, out.S);
}

bool
verifyDeterministicEncryption(
    Ciphertext const& ciphertext,
    CompressedPoint const& pk,
    std::uint64_t m,
    Scalar const& r) noexcept
{
    Ciphertext expected;
    if (!encrypt(pk, m, r, expected))
        return false;
    return ciphertext.R == expected.R && ciphertext.S == expected.S;
}

bool
canonicalEncryptedZero(
    Slice accountID,
    Slice mptIssuanceID,
    CompressedPoint const& pk,
    Ciphertext& out) noexcept
{
    if (accountID.size() != kAccountIDBytes ||
        mptIssuanceID.size() != kMPTIssuanceIDBytes)
        return false;

    // Validate pk is a strict compressed point.
    CompressedPoint pkCanon;
    if (!parseCompressedPoint(Slice(pk.data(), pk.size()), pkCanon))
        return false;

    static constexpr char const kDomain[] = "EncZero";
    std::uint8_t hash[32];
    detail::sha512HalfParts(
        hash,
        Slice(kDomain, sizeof(kDomain) - 1),
        accountID,
        mptIssuanceID,
        Slice(pkCanon.data(), pkCanon.size()));

    Scalar r;
    if (!detail::scalarReduceModOrder(hash, r) || scalarIsZero(r))
        return false;

    return encrypt(pkCanon, 0, r, out);
}

bool
isCanonicalEncryptedZero(
    Ciphertext const& ciphertext,
    Slice accountID,
    Slice mptIssuanceID,
    CompressedPoint const& pk) noexcept
{
    Ciphertext expected;
    if (!canonicalEncryptedZero(accountID, mptIssuanceID, pk, expected))
        return false;
    return ciphertext.R == expected.R && ciphertext.S == expected.S;
}

}  // namespace confidential
}  // namespace crypto
}  // namespace xrpl
