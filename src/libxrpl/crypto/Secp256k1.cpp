#include <xrpl/crypto/Secp256k1.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/detail/secp256k1_context.h>
#include <xrpl/crypto/secure_erase.h>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

namespace xrpl {
namespace {

[[nodiscard]] std::optional<Secp256k1Point>
pointFromPubkey(secp256k1_pubkey const& pubkey)
{
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

[[nodiscard]] bool
parsePubkey(Secp256k1Point const& point, secp256k1_pubkey& out)
{
    return secp256k1_ec_pubkey_parse(
               detail::secp256k1Context(), &out, point.data(), Secp256k1Point::kSerializedSize) ==
        1;
}

}  // namespace

//------------------------------------------------------------------------------

Secp256k1Point::Secp256k1Point(std::array<std::uint8_t, kSerializedSize> const& data) : buf_(data)
{
}

std::optional<Secp256k1Point>
Secp256k1Point::parse(Slice data)
{
    if (data.size() != kSerializedSize)
        return std::nullopt;

    // Compressed encodings must start with 0x02 or 0x03.
    if (data[0] != 0x02 && data[0] != 0x03)
        return std::nullopt;

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(detail::secp256k1Context(), &pubkey, data.data(), data.size()) !=
        1)
        return std::nullopt;

    std::array<std::uint8_t, kSerializedSize> out{};
    std::size_t len = out.size();
    if (secp256k1_ec_pubkey_serialize(
            detail::secp256k1Context(), out.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED) != 1 ||
        len != out.size())
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    // Reject any non-canonical re-encoding (should match input for valid points).
    if (!std::equal(out.begin(), out.end(), data.begin()))
        return std::nullopt;

    return Secp256k1Point{out};
}

void
Secp256k1Point::serialize(void* dest) const
{
    std::memcpy(dest, buf_.data(), buf_.size());
}

std::array<std::uint8_t, Secp256k1Point::kSerializedSize>
Secp256k1Point::serialize() const
{
    return buf_;
}

//------------------------------------------------------------------------------

Secp256k1Scalar::Secp256k1Scalar(std::array<std::uint8_t, kSerializedSize> const& data) : buf_(data)
{
}

Secp256k1Scalar::Secp256k1Scalar(Secp256k1Scalar const& other) : buf_(other.buf_)
{
}

Secp256k1Scalar&
Secp256k1Scalar::operator=(Secp256k1Scalar const& other)
{
    if (this != &other)
        buf_ = other.buf_;
    return *this;
}

Secp256k1Scalar::Secp256k1Scalar(Secp256k1Scalar&& other) noexcept : buf_(other.buf_)
{
    secureErase(other.buf_.data(), other.buf_.size());
}

Secp256k1Scalar&
Secp256k1Scalar::operator=(Secp256k1Scalar&& other) noexcept
{
    if (this != &other)
    {
        buf_ = other.buf_;
        secureErase(other.buf_.data(), other.buf_.size());
    }
    return *this;
}

Secp256k1Scalar::~Secp256k1Scalar()
{
    secureErase(buf_.data(), buf_.size());
}

std::optional<Secp256k1Scalar>
Secp256k1Scalar::parse(Slice data)
{
    if (data.size() != kSerializedSize)
        return std::nullopt;

    std::array<std::uint8_t, kSerializedSize> buf{};
    std::memcpy(buf.data(), data.data(), kSerializedSize);

    // Rejects zero and values >= curve order; constant-time in libsecp.
    if (secp256k1_ec_seckey_verify(detail::secp256k1Context(), buf.data()) != 1)
        return std::nullopt;

    return Secp256k1Scalar{buf};
}

void
Secp256k1Scalar::serialize(void* dest) const
{
    std::memcpy(dest, buf_.data(), buf_.size());
}

std::array<std::uint8_t, Secp256k1Scalar::kSerializedSize>
Secp256k1Scalar::serialize() const
{
    return buf_;
}

//------------------------------------------------------------------------------

std::optional<Secp256k1Point>
generatorMultiply(Secp256k1Scalar const& scalar)
{
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(detail::secp256k1Context(), &pubkey, scalar.data()) != 1)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }
    return pointFromPubkey(pubkey);
}

std::optional<Secp256k1Point>
pointMultiply(Secp256k1Point const& point, Secp256k1Scalar const& scalar)
{
    secp256k1_pubkey pubkey;
    if (!parsePubkey(point, pubkey))
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    if (secp256k1_ec_pubkey_tweak_mul(detail::secp256k1Context(), &pubkey, scalar.data()) != 1)
        return std::nullopt;

    return pointFromPubkey(pubkey);
}

std::optional<Secp256k1Point>
pointAdd(Secp256k1Point const& a, Secp256k1Point const& b)
{
    secp256k1_pubkey pa;
    secp256k1_pubkey pb;
    if (!parsePubkey(a, pa) || !parsePubkey(b, pb))
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    secp256k1_pubkey const* ins[2] = {&pa, &pb};
    secp256k1_pubkey out;
    // Returns 0 when the sum is the point at infinity.
    if (secp256k1_ec_pubkey_combine(detail::secp256k1Context(), &out, ins, 2) != 1)
        return std::nullopt;

    return pointFromPubkey(out);
}

std::optional<Secp256k1Point>
pointSubtract(Secp256k1Point const& a, Secp256k1Point const& b)
{
    secp256k1_pubkey pa;
    secp256k1_pubkey pb;
    if (!parsePubkey(a, pa) || !parsePubkey(b, pb))
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }

    secp256k1_ec_pubkey_negate(detail::secp256k1Context(), &pb);

    secp256k1_pubkey const* ins[2] = {&pa, &pb};
    secp256k1_pubkey out;
    if (secp256k1_ec_pubkey_combine(detail::secp256k1Context(), &out, ins, 2) != 1)
        return std::nullopt;

    return pointFromPubkey(out);
}

}  // namespace xrpl
