#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace xrpl {

/** Exact on-wire proof sizes. */
inline constexpr std::size_t kRegisterPoKSize = 64;
inline constexpr std::size_t kSendSigmaSize = 192;
inline constexpr std::size_t kConvertBackSigmaSize = 128;
inline constexpr std::size_t kClawbackSigmaSize = 64;

/** Opaque 32-byte digest supplied by the caller (transactors compute later). */
inline constexpr std::size_t kTransactionContextIDSize = 32;

/** Independent NUMS generator H for Pedersen commitments.

    Spec gap: both xls-0096 and the addendum require an "independent NUMS" H
    but do not specify derivation. This implementation uses try-and-increment:
    for counter = 0,1,... compute SHA-512-half of ASCII "CMPT_PEDERSEN_H" ||
    compressed G || 4-byte big-endian counter; interpret as 32-byte x with
    prefix 0x02 (even y); parse as secp256k1 point; reject if invalid or equal
    to G. The resulting H is cached.
*/
[[nodiscard]] Secp256k1Point const&
pedersenH();

/** Pedersen commitment PC = value·G + blinding·H.

    Value zero is supported (PC = blinding·H). Returns nullopt only if a group
    operation yields the point at infinity (astronomically rare for honest
    inputs).
*/
[[nodiscard]] std::optional<Secp256k1Point>
pedersenCommit(std::uint64_t value, Secp256k1Scalar const& blinding);

[[nodiscard]] std::optional<Secp256k1Point>
pedersenCommit(Secp256k1Field const& value, Secp256k1Scalar const& blinding);

/** Fiat–Shamir transcript: domain tag || compressed points || scalars.

    Spec gap: hash H() is unnamed in both docs. This code computes SHA-512 of
    the exact concatenated transcript bytes, then takes the first 32 bytes as
    a big-endian integer. If that integer is 0 or >= curve order n, appends a
    single counter byte (starting at 0x00) and re-hashes, incrementing the
    counter until the result is in [1, n-1]. That reduction is unspecified.
*/
class CompactTranscript
{
    std::vector<std::uint8_t> buf_;

public:
    void
    appendDomainTag(std::string_view tag);

    void
    append(Secp256k1Point const& point);

    void
    append(Secp256k1Scalar const& scalar);

    void
    append(Slice bytes);

    [[nodiscard]] std::optional<Secp256k1Scalar>
    challenge();
};

/** Reduce message bytes to a curve scalar via SHA-512 + first-32 + counter.

    Same algorithm as CompactTranscript::challenge (spec gap on H / Z_n).
    Used by EncZero and Fiat–Shamir challenges so callers do not reimplement.
*/
[[nodiscard]] std::optional<Secp256k1Scalar>
hashToCurveScalar(Slice message);

/** Schnorr PoK of sk for pk = sk·G. Domain "CMPT_POK_SK_REGISTER".
    Proof π = (e, s), 64 bytes. Equations (5)–(7).
*/
[[nodiscard]] std::optional<std::array<std::uint8_t, kRegisterPoKSize>>
proveRegisterPoK(Secp256k1Scalar const& sk, Secp256k1Point const& pk, Slice txContextID);

[[nodiscard]] bool
verifyRegisterPoK(Secp256k1Point const& pk, Slice proof, Slice txContextID);

/** Compact AND-composed Send sigma. Domain "CMPT_SEND_SIGMA".
    Proof π = (e, zm, zr, zb, zρ, zsk), 192 bytes. Equations (19)–(38).

    Spec inconsistency: xls-0096 stores each EncryptedAmount as a 66-byte
    (C1||C2) ciphertext, while the addendum’s Send proof uses shared C1 plus
    C2,i. This API accepts per-recipient 66-byte ciphertexts and REQUIRES
    identical C1 across them (returns nullopt/false if they differ).
*/
[[nodiscard]] std::optional<std::array<std::uint8_t, kSendSigmaSize>>
proveSendSigma(
    std::uint64_t amount,
    Secp256k1Scalar const& randomness,
    std::uint64_t balance,
    Secp256k1Scalar const& balanceBlinding,
    Secp256k1Scalar const& skA,
    std::span<Secp256k1Point const> recipientPks,
    Secp256k1Point const& senderPk,
    std::span<ElGamalCiphertext const> ciphertexts,
    Secp256k1Point const& pcM,
    Secp256k1Point const& pcB,
    ElGamalCiphertext const& balanceCiphertext,
    Slice txContextID);

[[nodiscard]] bool
verifySendSigma(
    std::span<Secp256k1Point const> recipientPks,
    Secp256k1Point const& senderPk,
    std::span<ElGamalCiphertext const> ciphertexts,
    Secp256k1Point const& pcM,
    Secp256k1Point const& pcB,
    ElGamalCiphertext const& balanceCiphertext,
    Slice proof,
    Slice txContextID);

/** Compact ConvertBack balance sigma. Domain "CMPT_CONVERTBACK_SIGMA".
    Proof π = (e, zb, zρ, zsk), 128 bytes. Equations (47)–(58).
*/
[[nodiscard]] std::optional<std::array<std::uint8_t, kConvertBackSigmaSize>>
proveConvertBackSigma(
    std::uint64_t balance,
    Secp256k1Scalar const& balanceBlinding,
    Secp256k1Scalar const& skA,
    Secp256k1Point const& senderPk,
    ElGamalCiphertext const& balanceCiphertext,
    Secp256k1Point const& pcB,
    Slice txContextID);

[[nodiscard]] bool
verifyConvertBackSigma(
    Secp256k1Point const& senderPk,
    ElGamalCiphertext const& balanceCiphertext,
    Secp256k1Point const& pcB,
    Slice proof,
    Slice txContextID);

/** Compact Chaum–Pedersen clawback. Domain "CMPT_CLAWBACK_SIGMA".
    Proof π = (e, zsk), 64 bytes. Equations (69)–(76).

    Hash includes m·G as a compressed point, not the scalar m (Remark 5.3).
    Spec gap: when m = 0, m·G is infinity and has no compressed encoding;
    prove/verify return nullopt/false for m = 0.
*/
[[nodiscard]] std::optional<std::array<std::uint8_t, kClawbackSigmaSize>>
proveClawbackSigma(
    std::uint64_t amount,
    Secp256k1Scalar const& issuerSk,
    Secp256k1Point const& issuerPk,
    ElGamalCiphertext const& issuerCiphertext,
    Slice txContextID);

[[nodiscard]] bool
verifyClawbackSigma(
    std::uint64_t amount,
    Secp256k1Point const& issuerPk,
    ElGamalCiphertext const& issuerCiphertext,
    Slice proof,
    Slice txContextID);

}  // namespace xrpl
