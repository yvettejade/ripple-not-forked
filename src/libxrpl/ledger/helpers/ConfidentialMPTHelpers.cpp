#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/digest.h>

#include <string_view>

namespace xrpl {

std::optional<confidential_mpt::Ciphertext>
confidentialMPTEncryptedZero(
    confidential_mpt::Point const& publicKey,
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID) noexcept
{
    static constexpr std::string_view kTag = "EncZero";
    // SPEC INCONSISTENCY (xls-0096 EncZero domain):
    // Spec hashes Account || Issuer || Currency. XLS-33 MPTs have no Currency;
    // this implementation substitutes MPTokenIssuanceID while keeping Issuer.
    // Interop requires agreement on that substitution (or a Currency encoding).
    auto const digest = sha512Half(Slice{kTag.data(), kTag.size()}, account, issuer, issuanceID);
    auto const randomness = confidential_mpt::reduceScalar(Slice{digest.data(), digest.size()});
    return randomness ? confidential_mpt::encryptZero(publicKey, *randomness) : std::nullopt;
}

}  // namespace xrpl
