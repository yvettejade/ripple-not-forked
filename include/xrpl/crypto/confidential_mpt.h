#pragma once

#include <xrpl/basics/Slice.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace xrpl {
namespace confidential_mpt {

/** Compressed secp256k1 point size (SEC1). */
inline constexpr std::size_t kPointBytes = 33;

/** Scalar size for secp256k1. */
inline constexpr std::size_t kScalarBytes = 32;

/** EC-ElGamal ciphertext: C1 || C2. */
inline constexpr std::size_t kCiphertextBytes = kPointBytes * 2;

/** Compact Schnorr key-registration proof (e || s). */
inline constexpr std::size_t kKeyRegProofBytes = kScalarBytes * 2;

/** Compact Send AND-composed sigma proof. */
inline constexpr std::size_t kSendSigmaBytes = kScalarBytes * 6;

/** Compact ConvertBack balance sigma proof. */
inline constexpr std::size_t kConvertBackSigmaBytes = kScalarBytes * 4;

/** Compact Clawback Chaum–Pedersen proof. */
inline constexpr std::size_t kClawbackProofBytes = kScalarBytes * 2;

/**
 * Single 64-bit Bulletproof: 16 compressed points + 5 scalars.
 * Used for ConvertBack remainder commitment PC_rem.
 */
inline constexpr std::size_t kSingleBulletproofPoints = 16;
inline constexpr std::size_t kSingleBulletproofBytes =
    kSingleBulletproofPoints * kPointBytes + 5 * kScalarBytes;  // 688

/**
 * Aggregated two-value 64-bit Bulletproof: 18 compressed points + 5 scalars.
 * Used for Send amount + remainder commitments (PC_m, PC_rem).
 */
inline constexpr std::size_t kAggregatedBulletproofPoints = 18;
inline constexpr std::size_t kAggregatedBulletproofBytes =
    kAggregatedBulletproofPoints * kPointBytes + 5 * kScalarBytes;  // 754

using Point = std::array<std::uint8_t, kPointBytes>;
using Scalar = std::array<std::uint8_t, kScalarBytes>;
using Ciphertext = std::array<std::uint8_t, kCiphertextBytes>;

inline constexpr std::string_view kDomainKeyReg = "CMPT_POK_SK_REGISTER";
inline constexpr std::string_view kDomainSend = "CMPT_SEND_SIGMA";
inline constexpr std::string_view kDomainConvertBack = "CMPT_CONVERTBACK_SIGMA";
inline constexpr std::string_view kDomainClawback = "CMPT_CLAWBACK_SIGMA";
inline constexpr std::string_view kDomainBulletproofSingle = "CMPT_BP_RANGE64";
inline constexpr std::string_view kDomainBulletproofAggregated = "CMPT_BP_RANGE64x2";

//------------------------------------------------------------------------------
// Validation
//------------------------------------------------------------------------------

[[nodiscard]] bool
isValidCompressedPoint(Slice data) noexcept;

[[nodiscard]] bool
isValidScalar(Slice data) noexcept;

/** Reduce a 32-byte big-endian integer modulo the secp256k1 group order. */
[[nodiscard]] std::optional<Scalar>
reduceScalar(Slice data) noexcept;

//------------------------------------------------------------------------------
// Ciphertext parse / serialize
//------------------------------------------------------------------------------

[[nodiscard]] std::optional<Ciphertext>
parseCiphertext(Slice data) noexcept;

[[nodiscard]] Ciphertext
serializeCiphertext(Point const& c1, Point const& c2) noexcept;

[[nodiscard]] Point
ciphertextC1(Ciphertext const& ct) noexcept;

[[nodiscard]] Point
ciphertextC2(Ciphertext const& ct) noexcept;

//------------------------------------------------------------------------------
// Group operations
//------------------------------------------------------------------------------

[[nodiscard]] std::optional<Point>
pointAdd(Point const& p, Point const& q) noexcept;

[[nodiscard]] std::optional<Point>
pointSub(Point const& p, Point const& q) noexcept;

[[nodiscard]] std::optional<Point>
pointMul(Point const& p, Scalar const& k) noexcept;

[[nodiscard]] std::optional<Point>
pointMulBase(Scalar const& k) noexcept;

/**
 * Independent NUMS Pedersen generator H.
 *
 * The Confidential MPT documents require an independent NUMS generator but
 * do not specify the derivation; this module uses a domain-tagged
 * hash-to-compressed-point search.
 */
[[nodiscard]] Point const&
pedersenH() noexcept;

[[nodiscard]] std::optional<Point>
pedersenCommit(std::uint64_t m, Scalar const& r) noexcept;

//------------------------------------------------------------------------------
// Deterministic EC-ElGamal
//------------------------------------------------------------------------------

[[nodiscard]] std::optional<Ciphertext>
encryptAmount(Point const& pk, std::uint64_t m, Scalar const& r) noexcept;

[[nodiscard]] bool
verifyCiphertext(Point const& pk, Ciphertext const& ct, std::uint64_t m, Scalar const& r) noexcept;

//------------------------------------------------------------------------------
// Homomorphic ciphertext ops / zero re-randomization
//------------------------------------------------------------------------------

[[nodiscard]] std::optional<Ciphertext>
ciphertextAdd(Ciphertext const& a, Ciphertext const& b) noexcept;

[[nodiscard]] std::optional<Ciphertext>
ciphertextSub(Ciphertext const& a, Ciphertext const& b) noexcept;

[[nodiscard]] std::optional<Ciphertext>
encryptZero(Point const& pk, Scalar const& r) noexcept;

/** Homomorphically add Enc_pk(0; e) (Send inbox re-randomization). */
[[nodiscard]] std::optional<Ciphertext>
rerandomizeWithScalar(Ciphertext const& ct, Point const& pk, Scalar const& e) noexcept;

//------------------------------------------------------------------------------
// Proof-prefix split (range bytes verified by Bulletproof APIs below)
//------------------------------------------------------------------------------

/**
 * Fixed-size compact sigma prefix plus any trailing range-proof bytes.
 * Splitters do not validate range-proof contents; use the Bulletproof
 * verify APIs on `rangeProof`.
 */
struct ProofPrefixView
{
    Slice sigma;
    Slice rangeProof;  // may be empty; validated separately
};

[[nodiscard]] std::optional<ProofPrefixView>
splitSendProof(Slice zkProof) noexcept;

[[nodiscard]] std::optional<ProofPrefixView>
splitConvertBackProof(Slice zkProof) noexcept;

//------------------------------------------------------------------------------
// Key registration (Schnorr PoK) — 64 bytes
//------------------------------------------------------------------------------

[[nodiscard]] std::optional<std::array<std::uint8_t, kKeyRegProofBytes>>
proveKeyRegistration(Scalar const& sk, Point const& pk, Slice context) noexcept;

[[nodiscard]] bool
verifyKeyRegistration(Point const& pk, Slice proof, Slice context) noexcept;

//------------------------------------------------------------------------------
// Send compact sigma — 192 bytes
//------------------------------------------------------------------------------

struct SendPublicInput
{
    std::vector<Point> recipientKeys;  // P_1 .. P_n, n >= 1
    Point senderKey;                   // P_A
    Point c1;
    std::vector<Point> c2;  // same size as recipientKeys
    Point amountCommitment;
    Point balanceCommitment;
    Point balanceC1;
    Point balanceC2;
};

struct SendWitness
{
    std::uint64_t m = 0;
    Scalar r{};
    std::uint64_t b = 0;
    Scalar rho{};
    Scalar sk{};
};

struct SendVerifyResult
{
    bool ok = false;
    /** Fiat–Shamir challenge; meaningful only when ok == true. */
    Scalar challenge{};
};

[[nodiscard]] std::optional<std::array<std::uint8_t, kSendSigmaBytes>>
proveSendSigma(SendPublicInput const& x, SendWitness const& w, Slice context) noexcept;

[[nodiscard]] SendVerifyResult
verifySendSigma(SendPublicInput const& x, Slice proof, Slice context) noexcept;

//------------------------------------------------------------------------------
// ConvertBack compact balance sigma — 128 bytes
//------------------------------------------------------------------------------

struct ConvertBackPublicInput
{
    Point holderKey;
    Point balanceC1;
    Point balanceC2;
    Point balanceCommitment;
};

struct ConvertBackWitness
{
    std::uint64_t b = 0;
    Scalar rho{};
    Scalar sk{};
};

[[nodiscard]] std::optional<std::array<std::uint8_t, kConvertBackSigmaBytes>>
proveConvertBackSigma(
    ConvertBackPublicInput const& x,
    ConvertBackWitness const& w,
    Slice context) noexcept;

[[nodiscard]] bool
verifyConvertBackSigma(ConvertBackPublicInput const& x, Slice proof, Slice context) noexcept;

//------------------------------------------------------------------------------
// Clawback compact Chaum–Pedersen — 64 bytes
//------------------------------------------------------------------------------

struct ClawbackPublicInput
{
    Point issuerKey;
    Point c1;
    Point c2;
    std::uint64_t m = 0;
};

[[nodiscard]] std::optional<std::array<std::uint8_t, kClawbackProofBytes>>
proveClawback(ClawbackPublicInput const& x, Scalar const& issuerSk, Slice context) noexcept;

[[nodiscard]] bool
verifyClawback(ClawbackPublicInput const& x, Slice proof, Slice context) noexcept;

//------------------------------------------------------------------------------
// Bulletproof range proofs (64-bit; single + aggregated)
//
// SPEC GAPS (xls-0096 / Updated_ConfidentialMPT_20260612 omit these; choices
// below are provisional, domain-separated, and shared by prove+verify):
//
// 1) Generator derivation: G_i / H_i / U use the same hash-to-compressed-point
//    search as pedersenH(), with tags CMPT_BP_G / CMPT_BP_H / CMPT_BP_U and a
//    big-endian index. Not specified by the documents.
// 2) Hash: Fiat–Shamir uses SHA-512Half (first 32 bytes of SHA-512) over an
//    ordered byte transcript, matching this module's sigma proofs.
// 3) Scalar reduction: digests must already lie in [1, q-1] (same as
//    secp256k1_ec_seckey_verify); no mod-q reduction of oversized digests.
//    Multi-challenge transcripts squeeze via CTX clone + absorb.
//    SPEC INCONSISTENCY: sigma proofs reject an out-of-range digest; the
//    Bulletproof transcript counter-retries up to 256 times instead.
// 4) Serialization order (points then scalars as listed):
//      A || S || T1 || T2 || τ_x || μ || t̂ || (L_j || R_j)_{j=1..log2(mn)}
//      || â || b̂
//    Wire scalars are canonical 32-byte big-endian in [0, q). Points are
//    strict SEC1 compressed (33 bytes) and must parse on secp256k1.
//------------------------------------------------------------------------------

/** Prove 0 <= value < 2^64 for V = value·G + blinding·H. */
[[nodiscard]] std::optional<std::array<std::uint8_t, kSingleBulletproofBytes>>
proveSingleBulletproof(
    Point const& commitment,
    std::uint64_t value,
    Scalar const& blinding,
    Slice context) noexcept;

[[nodiscard]] bool
verifySingleBulletproof(Point const& commitment, Slice proof, Slice context) noexcept;

/**
 * Prove 0 <= v0,v1 < 2^64 for V0 = v0·G + b0·H and V1 = v1·G + b1·H
 * (Send: amount commitment and remainder commitment PC_b - PC_m).
 */
[[nodiscard]] std::optional<std::array<std::uint8_t, kAggregatedBulletproofBytes>>
proveAggregatedBulletproof(
    Point const& commitment0,
    Point const& commitment1,
    std::uint64_t value0,
    Scalar const& blinding0,
    std::uint64_t value1,
    Scalar const& blinding1,
    Slice context) noexcept;

[[nodiscard]] bool
verifyAggregatedBulletproof(
    Point const& commitment0,
    Point const& commitment1,
    Slice proof,
    Slice context) noexcept;

}  // namespace confidential_mpt
}  // namespace xrpl
