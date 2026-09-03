#pragma once

#include <xrpl/basics/Slice.h>

#include <array>
#include <cstdint>

namespace xrpl {
namespace crypto {
namespace confidential {

/** Sizes for confidential-transfer EC-ElGamal over secp256k1. */
inline constexpr std::size_t kCompressedPointBytes = 33;
inline constexpr std::size_t kScalarBytes = 32;
inline constexpr std::size_t kCiphertextBytes = 66;  // R || S, each compressed
inline constexpr std::size_t kAccountIDBytes = 20;
inline constexpr std::size_t kMPTIssuanceIDBytes = 24;

using CompressedPoint = std::array<std::uint8_t, kCompressedPointBytes>;
using Scalar = std::array<std::uint8_t, kScalarBytes>;
using CiphertextBlob = std::array<std::uint8_t, kCiphertextBytes>;

/** EC-ElGamal ciphertext: (R, S) = (r·G, m·G + r·Pk). */
struct Ciphertext
{
    CompressedPoint R{};
    CompressedPoint S{};
};

/** Strict compressed secp256k1 point parse: length 33, prefix 02/03, on-curve,
    and re-serialization must equal the input bytes (rejects non-canonical forms). */
[[nodiscard]] bool
parseCompressedPoint(Slice in, CompressedPoint& out) noexcept;

[[nodiscard]] bool
serializeCompressedPoint(CompressedPoint const& in, CompressedPoint& out) noexcept;

/** Parse a 32-byte big-endian scalar; succeeds only if value is in [0, n). */
[[nodiscard]] bool
parseScalar(Slice in, Scalar& out) noexcept;

/** Parse a 32-byte big-endian scalar; succeeds only if value is in [1, n). */
[[nodiscard]] bool
parseNonZeroScalar(Slice in, Scalar& out) noexcept;

[[nodiscard]] bool
scalarIsZero(Scalar const& k) noexcept;

[[nodiscard]] bool
scalarAdd(Scalar const& a, Scalar const& b, Scalar& out) noexcept;

[[nodiscard]] bool
scalarSub(Scalar const& a, Scalar const& b, Scalar& out) noexcept;

[[nodiscard]] bool
scalarMul(Scalar const& a, Scalar const& b, Scalar& out) noexcept;

[[nodiscard]] bool
scalarNegate(Scalar const& a, Scalar& out) noexcept;

[[nodiscard]] bool
scalarFromUint64(std::uint64_t v, Scalar& out) noexcept;

/** Parse a 66-byte blob as two strict compressed points (R || S). */
[[nodiscard]] bool
parseCiphertext(Slice in, Ciphertext& out) noexcept;

[[nodiscard]] bool
serializeCiphertext(Ciphertext const& in, CiphertextBlob& out) noexcept;

/** Homomorphic ciphertext addition: (R1+R2, S1+S2). */
[[nodiscard]] bool
ciphertextAdd(Ciphertext const& a, Ciphertext const& b, Ciphertext& out) noexcept;

/** Homomorphic ciphertext subtraction: (R1-R2, S1-S2). */
[[nodiscard]] bool
ciphertextSub(Ciphertext const& a, Ciphertext const& b, Ciphertext& out) noexcept;

/** Encrypt plaintext m under Pk with randomness r: (rG, mG + r·Pk). */
[[nodiscard]] bool
encrypt(
    CompressedPoint const& pk,
    std::uint64_t m,
    Scalar const& r,
    Ciphertext& out) noexcept;

/** Deterministic encryption check for disclosed plaintext + randomness.
    Verifies ciphertext == Enc(pk, m; r). */
[[nodiscard]] bool
verifyDeterministicEncryption(
    Ciphertext const& ciphertext,
    CompressedPoint const& pk,
    std::uint64_t m,
    Scalar const& r) noexcept;

/** Canonical encrypted zero.
 *
 * XLS-0096 left the concrete hash and domain-byte layout underspecified
 * (raised for clarification). Selected behavior (per clarification):
 *   r = SHA512-Half("EncZero" || AccountID || MPTIssuanceID || Pk) mod n
 *   EncZero = (r·G, r·Pk)
 * where AccountID is 20 bytes, MPTIssuanceID is 24 bytes, and Pk is the
 * 33-byte compressed ElGamal public key.
 */
[[nodiscard]] bool
canonicalEncryptedZero(
    Slice accountID,
    Slice mptIssuanceID,
    CompressedPoint const& pk,
    Ciphertext& out) noexcept;

[[nodiscard]] bool
isCanonicalEncryptedZero(
    Ciphertext const& ciphertext,
    Slice accountID,
    Slice mptIssuanceID,
    CompressedPoint const& pk) noexcept;

}  // namespace confidential
}  // namespace crypto
}  // namespace xrpl
