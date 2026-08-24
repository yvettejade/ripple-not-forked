#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>

#include <array>
#include <cstdint>
#include <vector>

namespace xrpl {
namespace crypto {
namespace confidential {

inline constexpr std::size_t kSchnorrProofBytes = 64;  // challenge || response
inline constexpr std::size_t kSendSigmaProofBytes = 192;
inline constexpr std::size_t kBalanceSigmaProofBytes = 128;

using SchnorrProof = std::array<std::uint8_t, kSchnorrProofBytes>;
using SendSigmaProof = std::array<std::uint8_t, kSendSigmaProofBytes>;
using BalanceSigmaProof = std::array<std::uint8_t, kBalanceSigmaProofBytes>;

struct SendSigmaStatement
{
    std::vector<CompressedPoint> recipientPublicKeys;
    CompressedPoint senderPublicKey{};
    CompressedPoint sharedCiphertext{};
    std::vector<CompressedPoint> encryptedAmounts;
    CompressedPoint amountCommitment{};
    CompressedPoint balanceCommitment{};
    Ciphertext balanceCiphertext{};
};

struct SendSigmaWitness
{
    Scalar amount{};
    Scalar encryptionRandomness{};
    Scalar balance{};
    Scalar balanceBlinding{};
    Scalar senderSecret{};
};

struct BalanceSigmaStatement
{
    CompressedPoint senderPublicKey{};
    Ciphertext balanceCiphertext{};
    CompressedPoint balanceCommitment{};
};

struct BalanceSigmaWitness
{
    Scalar balance{};
    Scalar balanceBlinding{};
    Scalar senderSecret{};
};

/** Standard secp256k1 NUMS generator H used by libsecp256k1-zkp. */
[[nodiscard]] CompressedPoint const&
pedersenGenerator() noexcept;

[[nodiscard]] bool
pedersenCommit(
    Scalar const& value,
    Scalar const& blinding,
    CompressedPoint& commitment) noexcept;

[[nodiscard]] bool
verifySendSigmaProof(
    SendSigmaStatement const& statement,
    SendSigmaProof const& proof,
    Slice transactionContextID,
    Scalar* challenge = nullptr) noexcept;

[[nodiscard]] bool
createSendSigmaProof(
    SendSigmaStatement const& statement,
    SendSigmaWitness const& witness,
    SendSigmaProof& proof,
    Slice transactionContextID) noexcept;

[[nodiscard]] bool
verifyBalanceSigmaProof(
    BalanceSigmaStatement const& statement,
    BalanceSigmaProof const& proof,
    Slice transactionContextID) noexcept;

[[nodiscard]] bool
createBalanceSigmaProof(
    BalanceSigmaStatement const& statement,
    BalanceSigmaWitness const& witness,
    BalanceSigmaProof& proof,
    Slice transactionContextID) noexcept;

/** Schnorr proof of knowledge of x such that Pk = x·G.
 *
 * Wire form: 32-byte challenge c || 32-byte response z.
 *
 * Updated XLS-0096 Fiat–Shamir transcript:
 *   R = z·G − c·Pk
 *   c' = SHA512-Half("CMPT_POK_SK_REGISTER" || Pk || R || context)
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
 * Updated XLS-0096 compact clawback transcript:
 *   A1 = z·G − c·Pk
 *   A2 = z·R − c·(S − m·G)
 *   c' = SHA512-Half("CMPT_CLAWBACK_SIGMA" || Pk || R || S || m·G ||
 *                    A1 || A2 || context)
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
