#pragma once

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <cstddef>
#include <cstdint>
#include <span>

/** Bulletproof range proofs (Bünz et al., "Bulletproofs: Short Proofs for
    Confidential Transactions and More", sections 3-4) proving that each of
    m Pedersen commitments V_j = v_j·G + gamma_j·H opens to v_j in [0, 2^64).

    - Range proof: sections 4.1-4.3, aggregated over m values.
    - Inner-product argument: Protocols 1 and 2, verified with the single
      multi-exponentiation of section 3.1.
    - Fiat-Shamir (section 4.4): every challenge is SHA-256 of the transcript so
      far, reduced mod n. The transcript starts with "CMPT_BULLETPROOF",
      u8(m), the TransactionContextID and V_1..V_m; each challenge is appended
      after it is drawn.
    - Serialization in message order: A, S, T1, T2, tau_x, mu, t_hat,
      L_1, R_1, ..., L_k, R_k, a, b.

    The prover is intended for tests and client tooling.
*/
namespace xrpl::confidential {

inline constexpr std::size_t kRangeProofBits = 64;

/** Most commitments one proof covers; the generators support 64·2 bits. */
inline constexpr std::size_t kMaxRangeProofValues = kMaxBulletproofBits / kRangeProofBits;

/** Serialized size for m aggregated 64-bit values: (4 + 2k) points and
    5 scalars with k = log2(64·m).
*/
[[nodiscard]] constexpr std::size_t
rangeProofLength(std::size_t m)
{
    std::size_t k = 0;
    for (std::size_t bits = kRangeProofBits * m; bits > 1; bits /= 2)
        ++k;
    return (4 + 2 * k) * kEcPointLength + 5 * kScalarLength;
}

inline constexpr std::size_t kSingleRangeProofLength = rangeProofLength(1);
inline constexpr std::size_t kAggregatedRangeProofLength = rangeProofLength(2);

static_assert(kSingleRangeProofLength == 688);
static_assert(kAggregatedRangeProofLength == 754);

/** Prove that pedersenCommit(values[j], blindings[j]) opens to values[j].

    @throws std::invalid_argument unless 1 <= m <= kMaxRangeProofValues and
            the spans have the same length.
*/
[[nodiscard]] Buffer
proveRange(
    std::span<std::uint64_t const> values,
    std::span<Scalar const> blindings,
    uint256 const& contextID);

/** Verify a range proof over commitments (1 <= m <= kMaxRangeProofValues). */
[[nodiscard]] bool
verifyRange(std::span<Point const> commitments, Slice proof, uint256 const& contextID);

}  // namespace xrpl::confidential
