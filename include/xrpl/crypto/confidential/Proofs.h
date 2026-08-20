#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>

#include <array>
#include <cstdint>

namespace xrpl {
namespace crypto {
namespace confidential {

inline constexpr std::size_t kSchnorrProofBytes = 64;  // challenge || response

using SchnorrProof = std::array<std::uint8_t, kSchnorrProofBytes>;

/** Schnorr proof of knowledge of x such that Pk = x·G.
 *
 * Wire form: 32-byte challenge c || 32-byte response z.
 *
 * XLS-0096 left the Fiat–Shamir transcript unspecified (raised for
 * clarification). Selected behavior:
 *   R = z·G − c·Pk
 *   c' = SHA512-Half("CMT/SchnorrPoK" || Pk || R)
 * Accept iff c and z are canonical in [1, n), R serializes, and c' == c.
 *
 * Optional `extra` is hashed after R when non-empty, so callers can bind
 * transaction context once consensus defines those bytes:
 *   c' = SHA512-Half("CMT/SchnorrPoK" || Pk || R || extra)
 */
[[nodiscard]] bool
verifySchnorrProofOfKnowledge(
    CompressedPoint const& pk,
    SchnorrProof const& proof,
    Slice extra = {}) noexcept;

/** Compact clawback proof: knowledge of issuer secret x where
 *   Pk = x·G  and  (S − m·G) = x·R
 * for issuer ElGamal ciphertext (R, S) and claimed plaintext m.
 *
 * Wire form: 32-byte challenge c || 32-byte response z.
 *
 * XLS-0096 left the Fiat–Shamir transcript unspecified (raised for
 * clarification). Selected behavior:
 *   A1 = z·G − c·Pk
 *   A2 = z·R − c·(S − m·G)
 *   c' = SHA512-Half("CMT/Clawback" || Pk || R || S || m_be8 || A1 || A2)
 * where m_be8 is the plaintext as an 8-byte big-endian integer.
 * Accept iff c,z ∈ [1,n), points serialize, and c' == c.
 *
 * Optional `extra` is appended to the transcript when non-empty.
 */
[[nodiscard]] bool
verifyClawbackProof(
    CompressedPoint const& issuerPk,
    Ciphertext const& issuerCiphertext,
    std::uint64_t m,
    SchnorrProof const& proof,
    Slice extra = {}) noexcept;

/** Test/support prover for Schnorr PoK (same transcript as verifier). */
[[nodiscard]] bool
createSchnorrProofOfKnowledge(
    Scalar const& x,
    CompressedPoint const& pk,
    SchnorrProof& proof,
    Slice extra = {}) noexcept;

/** Test/support prover for clawback (same transcript as verifier). */
[[nodiscard]] bool
createClawbackProof(
    Scalar const& issuerSecret,
    CompressedPoint const& issuerPk,
    Ciphertext const& issuerCiphertext,
    std::uint64_t m,
    SchnorrProof& proof,
    Slice extra = {}) noexcept;

}  // namespace confidential
}  // namespace crypto
}  // namespace xrpl
