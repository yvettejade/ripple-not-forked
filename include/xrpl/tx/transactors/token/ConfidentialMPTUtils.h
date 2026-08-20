#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/XRPAmount.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace xrpl {

class ReadView;
class STTx;

namespace confidential_mpt {

inline constexpr std::size_t kSendProofBytes = 946;
inline constexpr std::size_t kConvertBackProofBytes = 816;
inline constexpr std::size_t kCommitmentBytes = 33;

[[nodiscard]] XRPAmount
proofBaseFee(ReadView const& view, STTx const& tx);

[[nodiscard]] bool
validPoint(Slice blob);

[[nodiscard]] bool
validCiphertext(Slice blob);

[[nodiscard]] std::optional<Blob>
addCiphertexts(Slice lhs, Slice rhs);

[[nodiscard]] std::optional<Blob>
subtractCiphertexts(Slice lhs, Slice rhs);

[[nodiscard]] std::optional<Blob>
canonicalZero(
    AccountID const& account,
    MPTID const& issuanceID,
    Slice publicKey);

[[nodiscard]] std::vector<std::uint8_t>
proofContext(
    std::uint16_t transactionType,
    AccountID const& account,
    MPTID const& issuanceID,
    std::uint32_t version);

}  // namespace confidential_mpt
}  // namespace xrpl
