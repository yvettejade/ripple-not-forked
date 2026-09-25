#include <xrpl/crypto/ElGamal.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/detail/secp256k1_context.h>
#include <xrpl/crypto/secure_erase.h>

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

namespace xrpl {
namespace {

/** Encode a uint64 plaintext as a 32-byte big-endian scalar (no bigint math). */
void
uint64ToScalarBE(std::uint64_t value, std::uint8_t* out32)
{
    std::memset(out32, 0, 32);
    for (int i = 0; i < 8; ++i)
        out32[31 - i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
}

[[nodiscard]] std::optional<Secp256k1Point>
generatorMultiplyUint64(std::uint64_t value)
{
    // Zero times G is infinity and cannot be represented; caller must special-case.
    if (value == 0)
        return std::nullopt;

    std::array<std::uint8_t, 32> scalar{};
    uint64ToScalarBE(value, scalar.data());

    // uint64 is always in [1, n-1] for secp256k1.
    secp256k1_pubkey pubkey;
    int const created =
        secp256k1_ec_pubkey_create(detail::secp256k1Context(), &pubkey, scalar.data());
    secureErase(scalar.data(), scalar.size());
    if (created != 1)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    std::array<std::uint8_t, Secp256k1Point::kSerializedSize> out{};
    std::size_t len = out.size();
    if (secp256k1_ec_pubkey_serialize(
            detail::secp256k1Context(), out.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED) != 1 ||
        len != out.size())
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }
    return Secp256k1Point::parse(makeSlice(out));
}

}  // namespace

ElGamalCiphertext::ElGamalCiphertext(Secp256k1Point const& c1, Secp256k1Point const& c2)
    : c1_(c1), c2_(c2)
{
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::parse(Slice data)
{
    if (data.size() != kSerializedSize)
        return std::nullopt;

    auto c1 = Secp256k1Point::parse(Slice(data.data(), Secp256k1Point::kSerializedSize));
    if (!c1)
        return std::nullopt;

    auto c2 = Secp256k1Point::parse(
        Slice(data.data() + Secp256k1Point::kSerializedSize, Secp256k1Point::kSerializedSize));
    if (!c2)
        return std::nullopt;

    return ElGamalCiphertext{*c1, *c2};
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::encrypt(
    std::uint64_t plaintext,
    Secp256k1Point const& publicKey,
    Secp256k1Scalar const& randomness)
{
    auto c1 = generatorMultiply(randomness);
    if (!c1)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    auto rY = pointMultiply(publicKey, randomness);
    if (!rY)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    if (plaintext == 0)
    {
        // C2 = 0*G + r*Y = r*Y
        return ElGamalCiphertext{*c1, *rY};
    }

    auto mG = generatorMultiplyUint64(plaintext);
    if (!mG)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    auto c2 = pointAdd(*mG, *rY);
    if (!c2)
        return std::nullopt;

    return ElGamalCiphertext{*c1, *c2};
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::add(ElGamalCiphertext const& other) const
{
    auto c1 = pointAdd(c1_, other.c1_);
    if (!c1)
        return std::nullopt;
    auto c2 = pointAdd(c2_, other.c2_);
    if (!c2)
        return std::nullopt;
    return ElGamalCiphertext{*c1, *c2};
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::subtract(ElGamalCiphertext const& other) const
{
    auto c1 = pointSubtract(c1_, other.c1_);
    if (!c1)
        return std::nullopt;
    auto c2 = pointSubtract(c2_, other.c2_);
    if (!c2)
        return std::nullopt;
    return ElGamalCiphertext{*c1, *c2};
}

void
ElGamalCiphertext::serialize(void* dest) const
{
    auto* out = static_cast<std::uint8_t*>(dest);
    c1_.serialize(out);
    c2_.serialize(out + Secp256k1Point::kSerializedSize);
}

std::array<std::uint8_t, ElGamalCiphertext::kSerializedSize>
ElGamalCiphertext::serialize() const
{
    std::array<std::uint8_t, kSerializedSize> out{};
    serialize(out.data());
    return out;
}

}  // namespace xrpl
