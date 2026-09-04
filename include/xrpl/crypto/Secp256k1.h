#pragma once

#include <xrpl/basics/Slice.h>

#include <array>
#include <cstdint>
#include <optional>

namespace xrpl {

class Secp256k1Scalar;

/** Canonical compressed secp256k1 group element (33 bytes).

    Only construct via parse() or group operations. Invalid encodings and
    the point at infinity are rejected (nullopt), never asserted.
*/
class Secp256k1Point
{
public:
    static constexpr std::size_t kSerializedSize = 33;

private:
    std::array<std::uint8_t, kSerializedSize> buf_{};

    explicit Secp256k1Point(std::array<std::uint8_t, kSerializedSize> const& data);

public:
    Secp256k1Point() = delete;

    /** Parse a canonical 33-byte compressed secp256k1 point.

        @return nullopt if size, prefix, or curve membership is invalid.
                Infinity is not a valid compressed encoding and is rejected.
    */
    [[nodiscard]] static std::optional<Secp256k1Point>
    parse(Slice data);

    /** Write the canonical 33-byte compressed encoding to dest. */
    void
    serialize(void* dest) const;

    [[nodiscard]] std::array<std::uint8_t, kSerializedSize>
    serialize() const;

    [[nodiscard]] std::uint8_t const*
    data() const noexcept
    {
        return buf_.data();
    }

    [[nodiscard]] static constexpr std::size_t
    size() noexcept
    {
        return kSerializedSize;
    }

    [[nodiscard]] Slice
    slice() const noexcept
    {
        return {buf_.data(), buf_.size()};
    }

    [[nodiscard]] bool
    operator==(Secp256k1Point const& other) const noexcept
    {
        return buf_ == other.buf_;
    }
};

/** Canonical nonzero secp256k1 scalar in [1, n-1] (32-byte big-endian).

    Used for externally supplied proof/encryption randomness. Secret material
    is wiped on destruction. Do not use for uint64 plaintexts; pass those to
    ElGamalCiphertext::encrypt directly.
*/
class Secp256k1Scalar
{
public:
    static constexpr std::size_t kSerializedSize = 32;

private:
    std::array<std::uint8_t, kSerializedSize> buf_{};

    explicit Secp256k1Scalar(std::array<std::uint8_t, kSerializedSize> const& data);

public:
    Secp256k1Scalar() = delete;

    Secp256k1Scalar(Secp256k1Scalar const& other);
    Secp256k1Scalar&
    operator=(Secp256k1Scalar const& other);

    Secp256k1Scalar(Secp256k1Scalar&& other) noexcept;
    Secp256k1Scalar&
    operator=(Secp256k1Scalar&& other) noexcept;

    ~Secp256k1Scalar();

    /** Parse a canonical 32-byte big-endian nonzero scalar below the curve order.

        @return nullopt for wrong size, zero, or value >= curve order.
    */
    [[nodiscard]] static std::optional<Secp256k1Scalar>
    parse(Slice data);

    /** Write the 32-byte big-endian encoding to dest. */
    void
    serialize(void* dest) const;

    [[nodiscard]] std::array<std::uint8_t, kSerializedSize>
    serialize() const;

    [[nodiscard]] std::uint8_t const*
    data() const noexcept
    {
        return buf_.data();
    }

    [[nodiscard]] static constexpr std::size_t
    size() noexcept
    {
        return kSerializedSize;
    }

    [[nodiscard]] Slice
    slice() const noexcept
    {
        return {buf_.data(), buf_.size()};
    }
};

/** Return scalar * G, or nullopt if the result cannot be serialized (should not
    occur for a validated scalar).
*/
[[nodiscard]] std::optional<Secp256k1Point>
generatorMultiply(Secp256k1Scalar const& scalar);

/** Return scalar * point, or nullopt on libsecp failure. */
[[nodiscard]] std::optional<Secp256k1Point>
pointMultiply(Secp256k1Point const& point, Secp256k1Scalar const& scalar);

/** Return a + b, or nullopt if the sum is the point at infinity. */
[[nodiscard]] std::optional<Secp256k1Point>
pointAdd(Secp256k1Point const& a, Secp256k1Point const& b);

/** Return a - b, or nullopt if the difference is the point at infinity. */
[[nodiscard]] std::optional<Secp256k1Point>
pointSubtract(Secp256k1Point const& a, Secp256k1Point const& b);

/** Field element in [0, n-1] (32-byte big-endian).

    Unlike Secp256k1Scalar, zero is allowed so witness values such as amount
    m = 0 can participate in modular arithmetic without going through
    Secp256k1Scalar::parse (which rejects 0). Secret material is wiped on
    destruction. Attacker-controlled proof scalars must still use
    Secp256k1Scalar::parse.
*/
class Secp256k1Field
{
public:
    static constexpr std::size_t kSerializedSize = 32;

private:
    std::array<std::uint8_t, kSerializedSize> buf_{};

    explicit Secp256k1Field(std::array<std::uint8_t, kSerializedSize> const& data);

public:
    Secp256k1Field() = delete;

    Secp256k1Field(Secp256k1Field const& other);
    Secp256k1Field&
    operator=(Secp256k1Field const& other);

    Secp256k1Field(Secp256k1Field&& other) noexcept;
    Secp256k1Field&
    operator=(Secp256k1Field&& other) noexcept;

    ~Secp256k1Field();

    /** Parse a 32-byte big-endian integer in [0, n-1].

        @return nullopt for wrong size or value >= curve order.
    */
    [[nodiscard]] static std::optional<Secp256k1Field>
    parse(Slice data);

    [[nodiscard]] static Secp256k1Field
    fromUint64(std::uint64_t value);

    [[nodiscard]] static Secp256k1Field
    fromScalar(Secp256k1Scalar const& scalar);

    [[nodiscard]] static Secp256k1Field
    zero() noexcept;

    [[nodiscard]] bool
    isZero() const noexcept;

    /** Convert to a nonzero scalar; nullopt if this field element is zero. */
    [[nodiscard]] std::optional<Secp256k1Scalar>
    toScalar() const;

    void
    serialize(void* dest) const;

    [[nodiscard]] std::array<std::uint8_t, kSerializedSize>
    serialize() const;

    [[nodiscard]] std::uint8_t const*
    data() const noexcept
    {
        return buf_.data();
    }

    [[nodiscard]] static constexpr std::size_t
    size() noexcept
    {
        return kSerializedSize;
    }

    [[nodiscard]] Slice
    slice() const noexcept
    {
        return {buf_.data(), buf_.size()};
    }
};

/** (a + b) mod n. */
[[nodiscard]] Secp256k1Field
fieldAdd(Secp256k1Field const& a, Secp256k1Field const& b);

/** (a * b) mod n. */
[[nodiscard]] Secp256k1Field
fieldMul(Secp256k1Field const& a, Secp256k1Field const& b);

/** (-a) mod n; zero maps to zero. */
[[nodiscard]] Secp256k1Field
fieldNegate(Secp256k1Field const& a);

/** (a - b) mod n. */
[[nodiscard]] Secp256k1Field
fieldSub(Secp256k1Field const& a, Secp256k1Field const& b);

/** Modular inverse in F_n; nullopt if a is zero. */
[[nodiscard]] std::optional<Secp256k1Field>
fieldInverse(Secp256k1Field const& a);

/** Return field * G, or nullopt if field is zero (point at infinity). */
[[nodiscard]] std::optional<Secp256k1Point>
generatorMultiply(Secp256k1Field const& field);

/** Return field * point, or nullopt if field is zero or on libsecp failure. */
[[nodiscard]] std::optional<Secp256k1Point>
pointMultiply(Secp256k1Point const& point, Secp256k1Field const& field);

}  // namespace xrpl
