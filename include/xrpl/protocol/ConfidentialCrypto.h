#pragma once

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>

#include <secp256k1.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

/** secp256k1 group primitives and EC-ElGamal encryption for XLS-0096
    Confidential MPTs.

    These routines verify public data (ciphertexts, keys, commitments and
    disclosed blinding factors) and are not constant-time.
*/
namespace xrpl::confidential {

/** Length of a compressed secp256k1 point (the specification's ecPubKeyLength). */
inline constexpr std::size_t kEcPointLength = 33;

/** Length of a big-endian secp256k1 scalar. */
inline constexpr std::size_t kScalarLength = 32;

/** Length of a serialized EC-ElGamal ciphertext (C1 || C2). */
inline constexpr std::size_t kElGamalCiphertextLength = 2 * kEcPointLength;

/** An integer modulo the secp256k1 group order n. */
class Scalar
{
    std::array<std::uint8_t, kScalarLength> bytes_{};

public:
    /** The zero scalar. */
    Scalar() = default;

    /** Parse a canonical 32-byte big-endian scalar.

        @return the scalar, or nullopt unless the input is exactly 32 bytes
                encoding a value less than n.
    */
    [[nodiscard]] static std::optional<Scalar>
    fromBytes(Slice s);

    [[nodiscard]] static Scalar
    fromUint64(std::uint64_t v);

    [[nodiscard]] bool
    isZero() const;

    /** Big-endian encoding. */
    [[nodiscard]] std::array<std::uint8_t, kScalarLength> const&
    bytes() const
    {
        return bytes_;
    }

    friend bool
    operator==(Scalar const&, Scalar const&) = default;
};

/** A secp256k1 group element, including the point at infinity. */
class Point
{
    secp256k1_pubkey pk_{};
    bool infinity_ = true;

public:
    /** The point at infinity (the group identity). */
    Point() = default;

    /** The standard secp256k1 base point G. */
    [[nodiscard]] static Point
    generator();

    /** Parse a 33-byte compressed point.

        @return the point, or nullopt unless the input is exactly 33 bytes
                with a 0x02/0x03 prefix and an x coordinate on the curve.
                The point at infinity has no such encoding.
    */
    [[nodiscard]] static std::optional<Point>
    fromBytes(Slice s);

    /** Compressed encoding, or nullopt for the point at infinity. */
    [[nodiscard]] std::optional<std::array<std::uint8_t, kEcPointLength>>
    bytes() const;

    [[nodiscard]] bool
    isInfinity() const
    {
        return infinity_;
    }

    friend Point
    operator+(Point const& a, Point const& b);

    friend Point
    operator-(Point const& a);

    friend Point
    operator-(Point const& a, Point const& b);

    friend Point
    operator*(Scalar const& k, Point const& p);

    friend bool
    operator==(Point const& a, Point const& b);

    /** k·G */
    friend Point
    mulGenerator(Scalar const& k);
};

[[nodiscard]] Point
mulGenerator(Scalar const& k);

/** True if the input is a valid 33-byte compressed secp256k1 point. */
[[nodiscard]] bool
isValidPoint(Slice s);

/** An EC-ElGamal ciphertext (C1, C2) = (r·G, m·G + r·Pk). */
struct ElGamalCiphertext
{
    Point c1;
    Point c2;

    /** Parse C1 || C2; both halves must be valid compressed points. */
    [[nodiscard]] static std::optional<ElGamalCiphertext>
    fromBytes(Slice s);

    /** Serialize as C1 || C2, or nullopt if either half is the point at
        infinity and therefore has no encoding.
    */
    [[nodiscard]] std::optional<Buffer>
    toBuffer() const;

    friend ElGamalCiphertext
    operator+(ElGamalCiphertext const& a, ElGamalCiphertext const& b);

    friend ElGamalCiphertext
    operator-(ElGamalCiphertext const& a, ElGamalCiphertext const& b);

    friend bool
    operator==(ElGamalCiphertext const&, ElGamalCiphertext const&) = default;
};

/** Enc_pk(m; r) = (r·G, m·G + r·pk). */
[[nodiscard]] ElGamalCiphertext
elGamalEncrypt(Scalar const& m, Scalar const& r, Point const& pk);

/** Deterministic plaintext-ciphertext check using a disclosed blinding
    factor: C1 == r·G and C2 == m·G + r·pk.
*/
[[nodiscard]] bool
verifyElGamalEncryption(
    ElGamalCiphertext const& ct,
    Scalar const& m,
    Scalar const& r,
    Point const& pk);

}  // namespace xrpl::confidential
