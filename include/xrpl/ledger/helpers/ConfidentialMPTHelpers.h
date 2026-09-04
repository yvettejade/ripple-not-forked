#pragma once

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/UintTypes.h>

#include <array>
#include <cstdint>
#include <optional>

namespace xrpl {

/** Parse a 66-byte ElGamal ciphertext from a ledger/tx VL blob. */
[[nodiscard]] std::optional<ElGamalCiphertext>
parseElGamalCiphertext(Slice data);

/** temBAD_CIPHERTEXT when length/points are invalid; tesSUCCESS otherwise. */
[[nodiscard]] NotTEC
validateElGamalCiphertext(Slice data);

/** Homomorphic add of two 66-byte ciphertext blobs. */
[[nodiscard]] std::optional<Blob>
homomorphicAddCiphertexts(Slice left, Slice right);

/** Homomorphic subtract of two 66-byte ciphertext blobs. */
[[nodiscard]] std::optional<Blob>
homomorphicSubCiphertexts(Slice left, Slice right);

/** Verify plaintext ElGamal: C1 = r·G, C2 = m·G + r·Pk (Convert reconstruct). */
[[nodiscard]] bool
verifyPlaintextElGamal(
    ElGamalCiphertext const& ciphertext,
    std::uint64_t amount,
    Secp256k1Point const& publicKey,
    Secp256k1Scalar const& randomness);

/** Spec §9.4 EncZero.

    r = H("EncZero" || Acct || Issuer || Curr) mod n; EncZero = (r·G, r·Pk).

    Spec gap: H is unspecified in xls-0096. Use the same SHA-512 + first-32-bytes
    + counter reduction as CompactTranscript::challenge / hashToCurveScalar.
    Domain tag is ASCII "EncZero" with no NUL terminator. Curr is the 24-byte
    MPTokenIssuanceID.
*/
[[nodiscard]] std::optional<Blob>
encZero(
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID,
    Secp256k1Point const& publicKey);

/** SHA-512-half of uint16 txType (BE) || Account (20) || issuance (24) ||
    uint32 sequence-or-ticket (BE) || optional TxSpecific suffix.

    Convert register PoK: empty TxSpecific (addendum omits it).
    ConvertBack: Account || CBS_Version (uint32 BE).
    Clawback: Holder || 0 (uint32 BE).
*/
[[nodiscard]] std::array<std::uint8_t, 32>
confidentialTxContextID(
    std::uint16_t txType,
    AccountID const& account,
    MPTID const& issuanceID,
    std::uint32_t sequenceOrTicket,
    Slice txSpecific = {});

}  // namespace xrpl
