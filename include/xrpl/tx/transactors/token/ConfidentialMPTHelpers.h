#pragma once

#include <xrpl/basics/base_uint.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>

#include <cstdint>
#include <initializer_list>
#include <optional>

/** Shared helpers for the XLS-0096 confidential MPT transactors. */
namespace xrpl::confidential_mpt {

/** XLS-0096 section 14.2: confidential transactions pay 10x the base fee. */
inline constexpr std::uint32_t kFeeMultiplier = 10;

/** kFeeMultiplier base fees plus one base fee per multisigner. */
[[nodiscard]] XRPAmount
baseFee(ReadView const& view, STTx const& tx);

/** The ciphertext in a Blob field, or nullopt if absent or malformed. */
[[nodiscard]] std::optional<confidential::ElGamalCiphertext>
ciphertext(STObject const& object, SF_VL const& field);

/** The point in a Blob field, or nullopt if absent or malformed. */
[[nodiscard]] std::optional<confidential::Point>
point(STObject const& object, SF_VL const& field);

/** The disclosed sfBlindingFactor, or nullopt unless it is a canonical scalar. */
[[nodiscard]] std::optional<confidential::Scalar>
blindingFactor(STTx const& tx);

/** temBAD_CIPHERTEXT unless each present field is a valid ciphertext. */
[[nodiscard]] NotTEC
checkCiphertexts(STTx const& tx, std::initializer_list<SF_VL const*> fields);

/** The Fiat-Shamir challenge e of a Send's sigma proof, its first scalar;
    nullopt unless it is a canonical, non-zero scalar.
*/
[[nodiscard]] std::optional<confidential::Scalar>
sendChallenge(STTx const& tx);

/** TransactionContextID of tx with TxSpecific = party || u32be(version). */
[[nodiscard]] uint256
contextID(STTx const& tx, AccountID const& party, std::uint32_t version);

/** The issuance's issuer key and, if configured, auditor key. */
struct IssuanceKeys
{
    confidential::Point issuer;
    std::optional<confidential::Point> auditor;
};

[[nodiscard]] std::optional<IssuanceKeys>
issuanceKeys(SLE const& issuance);

/** True if the MPToken has a holder key and the holder and issuer balances.
    The version is a default field, absent while it is 0.
*/
[[nodiscard]] bool
isInitialized(SLE const& mptoken);

/** True if the MPToken holds any XLS-0096 state: a holder key, an encrypted
    balance or mirror, or a non-zero version.
*/
[[nodiscard]] bool
hasConfidentialState(SLE const& mptoken);

/** Increments ConfidentialBalanceVersion, wrapping from 2^32 - 1 to 0. */
void
advanceVersion(SLE& mptoken);

/** tecNO_PERMISSION unless the transaction carries an auditor ciphertext
    exactly when the issuance has an auditor key.
*/
[[nodiscard]] TER
checkAuditorPolicy(STTx const& tx, IssuanceKeys const& keys);

/** Store a ciphertext; tecBAD_PROOF if a component is the identity. */
[[nodiscard]] TER
store(SLE& sle, SF_VL const& field, confidential::ElGamalCiphertext const& ct);

/** Homomorphically add ct to the stored balance, as store() does. */
[[nodiscard]] TER
credit(SLE& sle, SF_VL const& field, confidential::ElGamalCiphertext const& ct);

/** Homomorphically subtract ct from the stored balance, as store() does. */
[[nodiscard]] TER
debit(SLE& sle, SF_VL const& field, confidential::ElGamalCiphertext const& ct);

}  // namespace xrpl::confidential_mpt
