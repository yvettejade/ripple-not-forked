#pragma once

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/MPTIssue.h>

#include <cstddef>
#include <cstdint>
#include <optional>

namespace xrpl::confidential {

inline constexpr std::size_t publicKeySize = 33;
inline constexpr std::size_t ciphertextSize = 66;
inline constexpr std::size_t commitmentSize = 33;

bool
isValidPublicKey(Slice value);

bool
isValidCiphertext(Slice value);

std::optional<Blob>
addCiphertexts(Slice lhs, Slice rhs);

std::optional<Blob>
subtractCiphertexts(Slice lhs, Slice rhs);

std::optional<Blob>
canonicalEncryptedZero(
    AccountID const& account,
    MPTID const& issuanceID,
    Slice publicKey);

}  // namespace xrpl::confidential
