#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/crypto/secure_erase.h>

#include <secp256k1.h>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace xrpl {
namespace crypto {
namespace confidential {
namespace detail {

/** secp256k1 group order n (big-endian). */
inline constexpr std::array<std::uint8_t, 32> kCurveOrder{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

inline secp256k1_context const*
context() noexcept
{
    struct Holder
    {
        secp256k1_context* impl;
        Holder()
            : impl(secp256k1_context_create(
                  SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        {
        }
        ~Holder()
        {
            secp256k1_context_destroy(impl);
        }
    };
    static Holder const holder;
    return holder.impl;
}

/** SHA512-Half — same construction as xrpl::sha512Half (first 32 of SHA-512).
 *
 * XLS-0096 did not name the hash for EncZero / Fiat–Shamir (raised for
 * clarification); this module uses XRPL's existing SHA512-Half digest helper
 * construction via OpenSSL SHA-512.
 */
inline void
sha512Half(void const* data, std::size_t len, std::uint8_t out[32]) noexcept
{
    std::uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<unsigned char const*>(data), len, digest);
    std::memcpy(out, digest, 32);
    secureErase(digest, sizeof(digest));
}

template <class... Slices>
void
sha512HalfParts(std::uint8_t out[32], Slices const&... parts) noexcept
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    auto feed = [&](Slice s) {
        if (!s.empty())
            SHA512_Update(&ctx, s.data(), s.size());
    };
    (feed(parts), ...);
    std::uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_Final(digest, &ctx);
    std::memcpy(out, digest, 32);
    secureErase(digest, sizeof(digest));
}

inline bool
bnToScalar(BIGNUM const* bn, Scalar& out) noexcept
{
    if (BN_is_negative(bn) || BN_num_bytes(bn) > 32)
        return false;
    std::memset(out.data(), 0, out.size());
    return BN_bn2binpad(bn, out.data(), 32) == 32;
}

inline bool
scalarReduceModOrder(std::uint8_t const in[32], Scalar& out) noexcept
{
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr)
        return false;

    BIGNUM* v = BN_bin2bn(in, 32, nullptr);
    BIGNUM* n = BN_bin2bn(kCurveOrder.data(), 32, nullptr);
    BIGNUM* r = BN_new();
    bool ok = v && n && r && BN_mod(r, v, n, ctx) && bnToScalar(r, out);

    BN_free(r);
    BN_free(n);
    BN_free(v);
    BN_CTX_free(ctx);
    return ok;
}

inline bool
scalarLessThanOrder(Scalar const& k) noexcept
{
    return std::memcmp(k.data(), kCurveOrder.data(), 32) < 0;
}

inline bool
parsePubkey(CompressedPoint const& in, secp256k1_pubkey& out) noexcept
{
    return secp256k1_ec_pubkey_parse(
               context(), &out, in.data(), in.size()) == 1;
}

inline bool
serializePubkey(secp256k1_pubkey const& in, CompressedPoint& out) noexcept
{
    std::size_t len = out.size();
    return secp256k1_ec_pubkey_serialize(
               context(),
               out.data(),
               &len,
               &in,
               SECP256K1_EC_COMPRESSED) == 1 &&
        len == out.size();
}

inline bool
parseStrictCompressed(Slice in, secp256k1_pubkey& pk, CompressedPoint& out)
    noexcept
{
    if (in.size() != kCompressedPointBytes)
        return false;
    if (in[0] != 0x02 && in[0] != 0x03)
        return false;
    if (secp256k1_ec_pubkey_parse(context(), &pk, in.data(), in.size()) != 1)
        return false;
    if (!serializePubkey(pk, out))
        return false;
    // Strict: reject any encoding that does not round-trip byte-for-byte.
    return std::memcmp(out.data(), in.data(), kCompressedPointBytes) == 0;
}

inline bool
pointMulG(Scalar const& k, secp256k1_pubkey& out) noexcept
{
    if (scalarIsZero(k))
        return false;
    return secp256k1_ec_pubkey_create(context(), &out, k.data()) == 1;
}

inline bool
pointMul(secp256k1_pubkey const& p, Scalar const& k, secp256k1_pubkey& out)
    noexcept
{
    if (scalarIsZero(k))
        return false;
    out = p;
    return secp256k1_ec_pubkey_tweak_mul(context(), &out, k.data()) == 1;
}

inline bool
pointAdd(
    secp256k1_pubkey const& a,
    secp256k1_pubkey const& b,
    secp256k1_pubkey& out) noexcept
{
    secp256k1_pubkey const* arr[2] = {&a, &b};
    return secp256k1_ec_pubkey_combine(context(), &out, arr, 2) == 1;
}

inline bool
pointSub(
    secp256k1_pubkey const& a,
    secp256k1_pubkey const& b,
    secp256k1_pubkey& out) noexcept
{
    secp256k1_pubkey neg = b;
    secp256k1_ec_pubkey_negate(context(), &neg);
    return pointAdd(a, neg, out);
}

inline bool
pointMulGUint64(std::uint64_t m, secp256k1_pubkey& out) noexcept
{
    if (m == 0)
        return false;
    Scalar s{};
    if (!scalarFromUint64(m, s))
        return false;
    return pointMulG(s, out);
}

inline void
writeUint64BE(std::uint64_t v, std::uint8_t out[8]) noexcept
{
    for (int i = 7; i >= 0; --i)
    {
        out[i] = static_cast<std::uint8_t>(v & 0xff);
        v >>= 8;
    }
}

}  // namespace detail
}  // namespace confidential
}  // namespace crypto
}  // namespace xrpl
