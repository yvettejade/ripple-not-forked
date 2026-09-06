#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/Secp256k1.h>

#include <array>
#include <cstdint>
#include <optional>

namespace xrpl {

/** Single 64-bit Bulletproof: 16 compressed points + 5 scalars = 688 bytes.

    Used by ConfidentialMPTConvertBack on PC_rem (addendum §4).
*/
inline constexpr std::size_t kSingleBulletproofSize = 688;

/** Aggregated two-value 64-bit Bulletproof: 18 points + 5 scalars = 754 bytes.

    Used by ConfidentialMPTSend on (PC_m, PC_rem) (addendum §3).
*/
inline constexpr std::size_t kAggregatedBulletproofSize = 754;

/** Prove v ∈ [0, 2^64) for Pedersen commitment V = v·G + γ·H.

    Spec gap: Bulletproof generator vectors and Fiat–Shamir domain tags are
    unnamed. Generators G_i, H_i, U are NUMS via SHA-512-half of
    "CMPT_BP_G"|"CMPT_BP_H"|"CMPT_BP_U" plus a big-endian index (U uses
    index 0), even-y compressed parse, rejecting G and pedersenH().
    Transcript domain is "CMPT_BP_RANGE64". Challenges use CompactTranscript
    (same SHA-512 map as compact sigma).
*/
[[nodiscard]] std::optional<std::array<std::uint8_t, kSingleBulletproofSize>>
proveRange64(
    std::uint64_t value,
    Secp256k1Scalar const& blinding,
    Secp256k1Point const& commitment);

[[nodiscard]] bool
verifyRange64(Secp256k1Point const& commitment, Slice proof);

/** Prove v1, v2 ∈ [0, 2^64) for V1, V2. Domain "CMPT_BP_RANGE64_AGG2". */
[[nodiscard]] std::optional<std::array<std::uint8_t, kAggregatedBulletproofSize>>
proveRange64Aggregated(
    std::uint64_t value1,
    Secp256k1Scalar const& blinding1,
    Secp256k1Point const& commitment1,
    std::uint64_t value2,
    Secp256k1Scalar const& blinding2,
    Secp256k1Point const& commitment2);

[[nodiscard]] bool
verifyRange64Aggregated(
    Secp256k1Point const& commitment1,
    Secp256k1Point const& commitment2,
    Slice proof);

}  // namespace xrpl
