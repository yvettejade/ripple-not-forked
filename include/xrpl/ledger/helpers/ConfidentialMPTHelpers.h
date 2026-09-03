#pragma once

#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/UintTypes.h>

#include <optional>

namespace xrpl {

/** Return XLS-0096's deterministic encrypted zero for an MPT holder. */
[[nodiscard]] std::optional<confidential_mpt::Ciphertext>
confidentialMPTEncryptedZero(
    confidential_mpt::Point const& publicKey,
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID) noexcept;

}  // namespace xrpl
