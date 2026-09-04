#include <xrpl/crypto/Secp256k1.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/detail/secp256k1_context.h>
#include <xrpl/crypto/secure_erase.h>

#include <openssl/bn.h>

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

//------------------------------------------------------------------------------

namespace {

/** secp256k1 group order n (big-endian). */
std::array<std::uint8_t, 32> const&
curveOrderBE()
{
    static std::array<std::uint8_t, 32> const kOrder = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
        0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    return kOrder;
}

BIGNUM*
curveOrderBN()
{
    // Lazy-init once; never freed (process lifetime).
    static BIGNUM* const kN = BN_bin2bn(curveOrderBE().data(), 32, nullptr);
    return kN;
}

[[nodiscard]] std::array<std::uint8_t, 32>
bnToBe32(BIGNUM const* bn)
{
    std::array<std::uint8_t, 32> out{};
    // BN_bn2binpad returns -1 on error; order-reduced values always fit.
    if (BN_bn2binpad(bn, out.data(), 32) != 32)
    {
        // LCOV_EXCL_START
        out.fill(0);
        // LCOV_EXCL_STOP
    }
    return out;
}

}  // namespace

Secp256k1Field::Secp256k1Field(std::array<std::uint8_t, kSerializedSize> const& data) : buf_(data)
{
}

Secp256k1Field::Secp256k1Field(Secp256k1Field const& other) : buf_(other.buf_)
{
}

Secp256k1Field&
Secp256k1Field::operator=(Secp256k1Field const& other)
{
    if (this != &other)
        buf_ = other.buf_;
    return *this;
}

Secp256k1Field::Secp256k1Field(Secp256k1Field&& other) noexcept : buf_(other.buf_)
{
    secureErase(other.buf_.data(), other.buf_.size());
}

Secp256k1Field&
Secp256k1Field::operator=(Secp256k1Field&& other) noexcept
{
    if (this != &other)
    {
        buf_ = other.buf_;
        secureErase(other.buf_.data(), other.buf_.size());
    }
    return *this;
}

Secp256k1Field::~Secp256k1Field()
{
    secureErase(buf_.data(), buf_.size());
}

std::optional<Secp256k1Field>
Secp256k1Field::parse(Slice data)
{
    if (data.size() != kSerializedSize)
        return std::nullopt;

    std::array<std::uint8_t, kSerializedSize> buf{};
    std::memcpy(buf.data(), data.data(), kSerializedSize);

    // Allow zero; reject values >= curve order.
    bool allZero = true;
    for (auto b : buf)
    {
        if (b != 0)
        {
            allZero = false;
            break;
        }
    }
    if (!allZero)
    {
        if (secp256k1_ec_seckey_verify(detail::secp256k1Context(), buf.data()) != 1)
            return std::nullopt;
    }

    return Secp256k1Field{buf};
}

Secp256k1Field
Secp256k1Field::fromUint64(std::uint64_t value)
{
    std::array<std::uint8_t, kSerializedSize> buf{};
    for (int i = 0; i < 8; ++i)
        buf[31 - i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
    return Secp256k1Field{buf};
}

Secp256k1Field
Secp256k1Field::fromScalar(Secp256k1Scalar const& scalar)
{
    std::array<std::uint8_t, kSerializedSize> buf{};
    scalar.serialize(buf.data());
    return Secp256k1Field{buf};
}

Secp256k1Field
Secp256k1Field::zero() noexcept
{
    return Secp256k1Field{std::array<std::uint8_t, kSerializedSize>{}};
}

bool
Secp256k1Field::isZero() const noexcept
{
    for (auto b : buf_)
    {
        if (b != 0)
            return false;
    }
    return true;
}

std::optional<Secp256k1Scalar>
Secp256k1Field::toScalar() const
{
    return Secp256k1Scalar::parse(slice());
}

void
Secp256k1Field::serialize(void* dest) const
{
    std::memcpy(dest, buf_.data(), buf_.size());
}

std::array<std::uint8_t, Secp256k1Field::kSerializedSize>
Secp256k1Field::serialize() const
{
    return buf_;
}

Secp256k1Field
fieldAdd(Secp256k1Field const& a, Secp256k1Field const& b)
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* ba = BN_bin2bn(a.data(), 32, nullptr);
    BIGNUM* bb = BN_bin2bn(b.data(), 32, nullptr);
    BIGNUM* br = BN_new();
    BN_mod_add(br, ba, bb, curveOrderBN(), ctx);
    auto out = bnToBe32(br);
    BN_clear_free(ba);
    BN_clear_free(bb);
    BN_clear_free(br);
    BN_CTX_free(ctx);
    // Result is in [0, n-1] by construction.
    return *Secp256k1Field::parse(makeSlice(out));
}

Secp256k1Field
fieldMul(Secp256k1Field const& a, Secp256k1Field const& b)
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* ba = BN_bin2bn(a.data(), 32, nullptr);
    BIGNUM* bb = BN_bin2bn(b.data(), 32, nullptr);
    BIGNUM* br = BN_new();
    BN_mod_mul(br, ba, bb, curveOrderBN(), ctx);
    auto out = bnToBe32(br);
    BN_clear_free(ba);
    BN_clear_free(bb);
    BN_clear_free(br);
    BN_CTX_free(ctx);
    return *Secp256k1Field::parse(makeSlice(out));
}

Secp256k1Field
fieldNegate(Secp256k1Field const& a)
{
    if (a.isZero())
        return Secp256k1Field::zero();

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* ba = BN_bin2bn(a.data(), 32, nullptr);
    BIGNUM* br = BN_new();
    BN_mod_sub(br, curveOrderBN(), ba, curveOrderBN(), ctx);
    auto out = bnToBe32(br);
    BN_clear_free(ba);
    BN_clear_free(br);
    BN_CTX_free(ctx);
    return *Secp256k1Field::parse(makeSlice(out));
}

std::optional<Secp256k1Point>
generatorMultiply(Secp256k1Field const& field)
{
    auto const s = field.toScalar();
    if (!s)
        return std::nullopt;
    return generatorMultiply(*s);
}

std::optional<Secp256k1Point>
pointMultiply(Secp256k1Point const& point, Secp256k1Field const& field)
{
    auto const s = field.toScalar();
    if (!s)
        return std::nullopt;
    return pointMultiply(point, *s);
}

}  // namespace xrpl
