#pragma once

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

/** Compact Fiat-Shamir sigma proofs for XLS-0096 Confidential MPTs, as
    specified in Updated_ConfidentialMPT_20260612.md. Each proof transmits the
    challenge e followed by the responses; the verifier reconstructs the
    first-round commitments and accepts iff the recomputed challenge equals e.

    Provers take secret witnesses and are intended for tests and client
    tooling; validators only call the verifiers.
*/
namespace xrpl::confidential {

/** (e, s), section 2.4. */
inline constexpr std::size_t kSchnorrProofLength = 2 * kScalarLength;

/** (e, z_m, z_r, z_b, z_rho, z_sk), section 3.5. */
inline constexpr std::size_t kSendSigmaProofLength = 6 * kScalarLength;

/** (e, z_b, z_rho, z_sk), section 4.5. */
inline constexpr std::size_t kConvertBackSigmaProofLength = 4 * kScalarLength;

/** (e, z_sk), section 5.5. */
inline constexpr std::size_t kClawbackProofLength = 2 * kScalarLength;

/** Proof of knowledge of sk for pk = sk·G, bound to a transaction (eq. 5). */
[[nodiscard]] Buffer
proveKnowledge(Scalar const& secretKey, uint256 const& contextID);

[[nodiscard]] bool
verifyKnowledge(Point const& publicKey, Slice proof, uint256 const& contextID);

/** Public statement of the combined ConfidentialMPTSend relation (eq. 19). */
struct SendStatement
{
    // P_1..P_n: sender, destination, issuer and, if configured, auditor.
    std::vector<Point> recipientKeys;
    // P_A, the sender's key. It must equal P_1: the debit subtracts the
    // amount encrypted under P_1 from the balance decryptable under P_A, and
    // the proof relates the two only when they are the same key.
    Point senderKey;
    // C1 and C2_1..C2_n of the transfer amount ciphertexts.
    Point c1;
    std::vector<Point> c2;
    Point amountCommitment;
    Point balanceCommitment;
    // (B1, B2), the sender's spending balance.
    ElGamalCiphertext balance;
};

struct SendWitness
{
    Scalar amount;
    Scalar randomness;
    Scalar balance;
    Scalar balanceBlinding;
    Scalar secretKey;
};

[[nodiscard]] Buffer
proveSend(SendStatement const& statement, SendWitness const& witness, uint256 const& contextID);

/** Verify a Send sigma proof.

    @return the challenge e on success. It doubles as the inbox
            re-randomization scalar of eq. (11)-(12).
*/
[[nodiscard]] std::optional<Scalar>
verifySend(SendStatement const& statement, Slice proof, uint256 const& contextID);

/** Public statement of the balance linkage relation R_bal (eq. 47). */
struct BalanceStatement
{
    Point key;
    ElGamalCiphertext balance;
    Point balanceCommitment;
};

[[nodiscard]] Buffer
proveBalance(
    BalanceStatement const& statement,
    Scalar const& balance,
    Scalar const& balanceBlinding,
    Scalar const& secretKey,
    uint256 const& contextID);

[[nodiscard]] bool
verifyBalance(BalanceStatement const& statement, Slice proof, uint256 const& contextID);

/** Chaum-Pedersen proof that the issuer mirror encrypts amount (eq. 69). */
[[nodiscard]] Buffer
proveClawback(
    Point const& issuerKey,
    ElGamalCiphertext const& mirror,
    Scalar const& amount,
    Scalar const& issuerSecretKey,
    uint256 const& contextID);

[[nodiscard]] bool
verifyClawback(
    Point const& issuerKey,
    ElGamalCiphertext const& mirror,
    Scalar const& amount,
    Slice proof,
    uint256 const& contextID);

}  // namespace xrpl::confidential
