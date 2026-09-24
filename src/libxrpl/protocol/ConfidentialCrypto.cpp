#include <xrpl/protocol/ConfidentialCrypto.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/detail/secp256k1.h>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

namespace xrpl::confidential {

std::optional<Scalar>
Scalar::fromBytes(Slice s)
{
    if (s.size() != kScalarLength)
        return std::nullopt;

    Scalar result;
    std::memcpy(result.bytes_.data(), s.data(), kScalarLength);

    // secp256k1_ec_seckey_verify accepts exactly [1, n-1]; zero is a valid
    // scalar here and is handled separately.
    if (!result.isZero() &&
        secp256k1_ec_seckey_verify(secp256k1Context(), result.bytes_.data()) != 1)
        return std::nullopt;

    return result;
}

Scalar
Scalar::fromUint64(std::uint64_t v)
{
    Scalar result;
    for (std::size_t i = 0; i < sizeof(v); ++i)
        result.bytes_[kScalarLength - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    return result;
}

bool
Scalar::isZero() const
{
    return std::ranges::all_of(bytes_, [](std::uint8_t b) { return b == 0; });
}

Point
Point::generator()
{
    return mulGenerator(Scalar::fromUint64(1));
}

std::optional<Point>
Point::fromBytes(Slice s)
{
    if (s.size() != kEcPointLength || (s[0] != 0x02 && s[0] != 0x03))
        return std::nullopt;

    Point result;
    if (secp256k1_ec_pubkey_parse(secp256k1Context(), &result.pk_, s.data(), s.size()) != 1)
        return std::nullopt;

    result.infinity_ = false;
    return result;
}

std::optional<std::array<std::uint8_t, kEcPointLength>>
Point::bytes() const
{
    if (infinity_)
        return std::nullopt;

    std::array<std::uint8_t, kEcPointLength> out{};
    std::size_t len = out.size();
    if (secp256k1_ec_pubkey_serialize(
            secp256k1Context(), out.data(), &len, &pk_, SECP256K1_EC_COMPRESSED) != 1 ||
        len != out.size())
        return std::nullopt;  // LCOV_EXCL_LINE

    return out;
}

Point
operator+(Point const& a, Point const& b)
{
    if (a.infinity_)
        return b;
    if (b.infinity_)
        return a;

    // secp256k1_ec_pubkey_combine fails only when the sum is the point at
    // infinity, because both inputs are valid points.
    std::array<secp256k1_pubkey const*, 2> const ins{&a.pk_, &b.pk_};
    Point result;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &result.pk_, ins.data(), ins.size()) == 1)
        result.infinity_ = false;
    return result;
}

Point
operator-(Point const& a)
{
    Point result = a;
    if (!result.infinity_ && secp256k1_ec_pubkey_negate(secp256k1Context(), &result.pk_) != 1)
        return Point{};  // LCOV_EXCL_LINE
    return result;
}

Point
operator-(Point const& a, Point const& b)
{
    return a + (-b);
}

Point
operator*(Scalar const& k, Point const& p)
{
    if (p.infinity_ || k.isZero())
        return Point{};

    Point result = p;
    if (secp256k1_ec_pubkey_tweak_mul(secp256k1Context(), &result.pk_, k.bytes().data()) != 1)
        return Point{};  // LCOV_EXCL_LINE
    return result;
}

bool
operator==(Point const& a, Point const& b)
{
    if (a.infinity_ || b.infinity_)
        return a.infinity_ == b.infinity_;
    return secp256k1_ec_pubkey_cmp(secp256k1Context(), &a.pk_, &b.pk_) == 0;
}

Point
mulGenerator(Scalar const& k)
{
    if (k.isZero())
        return Point{};

    Point result;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &result.pk_, k.bytes().data()) != 1)
        return Point{};  // LCOV_EXCL_LINE
    result.infinity_ = false;
    return result;
}

bool
isValidPoint(Slice s)
{
    return Point::fromBytes(s).has_value();
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::fromBytes(Slice s)
{
    if (s.size() != kElGamalCiphertextLength)
        return std::nullopt;

    auto const c1 = Point::fromBytes(Slice(s.data(), kEcPointLength));
    auto const c2 = Point::fromBytes(Slice(s.data() + kEcPointLength, kEcPointLength));
    if (!c1 || !c2)
        return std::nullopt;

    return ElGamalCiphertext{.c1 = *c1, .c2 = *c2};
}

std::optional<Buffer>
ElGamalCiphertext::toBuffer() const
{
    auto const b1 = c1.bytes();
    auto const b2 = c2.bytes();
    if (!b1 || !b2)
        return std::nullopt;

    Buffer out(kElGamalCiphertextLength);
    std::memcpy(out.data(), b1->data(), kEcPointLength);
    std::memcpy(out.data() + kEcPointLength, b2->data(), kEcPointLength);
    return out;
}

ElGamalCiphertext
operator+(ElGamalCiphertext const& a, ElGamalCiphertext const& b)
{
    return ElGamalCiphertext{.c1 = a.c1 + b.c1, .c2 = a.c2 + b.c2};
}

ElGamalCiphertext
operator-(ElGamalCiphertext const& a, ElGamalCiphertext const& b)
{
    return ElGamalCiphertext{.c1 = a.c1 - b.c1, .c2 = a.c2 - b.c2};
}

ElGamalCiphertext
elGamalEncrypt(Scalar const& m, Scalar const& r, Point const& pk)
{
    return ElGamalCiphertext{.c1 = mulGenerator(r), .c2 = mulGenerator(m) + r * pk};
}

bool
verifyElGamalEncryption(
    ElGamalCiphertext const& ct,
    Scalar const& m,
    Scalar const& r,
    Point const& pk)
{
    if (pk.isInfinity())
        return false;
    return ct == elGamalEncrypt(m, r, pk);
}

}  // namespace xrpl::confidential
