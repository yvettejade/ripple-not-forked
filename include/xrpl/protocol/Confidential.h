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

/** Pedersen commitment C = v·G + r·H with a NUMS H. 33 compressed bytes. */
[[nodiscard]] std::optional<Buffer>
pedersenCommit(std::uint64_t v, uint256 const& r);

/** Clawback DLEQ: issuer Enc=(R,S) encrypts `m`. Witness is issuer sk (S-mG = sk·R). */
[[nodiscard]] std::optional<Buffer>
clawbackProve(
    Slice const& issuerCt,
    Slice const& issuerPk,
    std::uint64_t m,
    Slice const& issuerSk,
    Slice const& transcript);

[[nodiscard]] bool
clawbackVerify(
    Slice const& issuerCt,
    Slice const& issuerPk,
    std::uint64_t m,
    Slice const& proof,
    Slice const& transcript);

struct ConvertBackProof
{
    Buffer holderEnc;
    Buffer issuerEnc;
    Buffer auditorEnc;
    Buffer balanceCommitment;
    Buffer zkProof;
};

[[nodiscard]] std::optional<ConvertBackProof>
convertBackProve(
    Slice const& holderPk,
    Slice const& holderSk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    std::uint64_t balance,
    uint256 const& r,
    uint256 const& gamma,
    Slice const& transcript);

[[nodiscard]] bool
convertBackVerify(
    Slice const& holderPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    Slice const& holderEnc,
    Slice const& issuerEnc,
    std::optional<Slice> const& auditorEnc,
    uint256 const& r,
    Slice const& balanceCommitment,
    Slice const& zkProof,
    Slice const& transcript);

struct SendProof
{
    Buffer senderEnc;
    Buffer destEnc;
    Buffer issuerEnc;
    Buffer auditorEnc;
    Buffer amountCommitment;
    Buffer balanceCommitment;
    Buffer zkProof;
};

[[nodiscard]] std::optional<SendProof>
sendProve(
    Slice const& senderPk,
    Slice const& senderSk,
    Slice const& destPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    std::uint64_t balance,
    uint256 const& r,
    uint256 const& gamma,
    Slice const& transcript);

[[nodiscard]] bool
sendVerify(
    Slice const& senderPk,
    Slice const& destPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    Slice const& senderEnc,
    Slice const& destEnc,
    Slice const& issuerEnc,
    std::optional<Slice> const& auditorEnc,
    Slice const& amountCommitment,
    Slice const& balanceCommitment,
    Slice const& zkProof,
    Slice const& transcript);

[[nodiscard]] Buffer
clawbackTranscript(AccountID const& issuer, AccountID const& holder, MPTID const& mptId);

[[nodiscard]] Buffer
convertBackTranscript(AccountID const& account, MPTID const& mptId, std::uint32_t version);

[[nodiscard]] Buffer
sendTranscript(
    AccountID const& sender,
    AccountID const& dest,
    MPTID const& mptId,
    std::uint32_t version);

}  // namespace xrpl
