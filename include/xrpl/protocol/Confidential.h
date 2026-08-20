#pragma once

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/UintTypes.h>

#include <cstdint>
#include <optional>

namespace xrpl {

/** True if `key` is a 33-byte compressed secp256k1 public key. */
[[nodiscard]] bool
isConfidentialPubKey(Slice const& key);

/** True if `ct` is a 66-byte pair of valid compressed secp256k1 points. */
[[nodiscard]] bool
isConfidentialCiphertext(Slice const& ct);

/** True if `scalar` is a valid secp256k1 secret key (in (0, n)). */
[[nodiscard]] bool
isConfidentialScalar(uint256 const& scalar);

/** Enc(m, r, pk) = (r·G, m·G + r·pk). Returns 66 bytes, or nullopt on bad inputs. */
[[nodiscard]] std::optional<Buffer>
elgamalEncrypt(Slice const& pk, std::uint64_t m, uint256 const& r);

/** Homomorphic ciphertext addition. */
[[nodiscard]] std::optional<Buffer>
elgamalAdd(Slice const& a, Slice const& b);

/** Homomorphic ciphertext subtraction. */
[[nodiscard]] std::optional<Buffer>
elgamalSub(Slice const& a, Slice const& b);

/** Canonical EncZero for a holder of `mptId`: r = H("EncZero" || acct || issuer || mptId) mod n. */
[[nodiscard]] std::optional<Buffer>
encZero(AccountID const& account, AccountID const& issuer, MPTID const& mptId, Slice const& pk);

/** True if `ciphertext` equals Enc(m, r, pk). */
[[nodiscard]] bool
elgamalMatches(Slice const& ciphertext, Slice const& pk, std::uint64_t m, uint256 const& r);

/** Domain-separated Schnorr transcript for ConfidentialMPTConvert key registration. */
[[nodiscard]] Buffer
convertSchnorrTranscript(AccountID const& account, MPTID const& mptId);

/** Schnorr PoK of sk for pk = sk·G. Proof is 64 bytes (c || s). */
[[nodiscard]] std::optional<Buffer>
schnorrProve(Slice const& pk, Slice const& sk, Slice const& transcript);

[[nodiscard]] bool
schnorrVerify(Slice const& pk, Slice const& proof, Slice const& transcript);

}  // namespace xrpl
