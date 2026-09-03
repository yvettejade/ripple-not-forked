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
    // XLS-0096 specifies Account || Issuer || Currency, but XLS-33 MPTs have
    // an issuance ID rather than a Currency field. The issuance ID is the
    // canonical token-domain replacement while retaining Issuer explicitly.
    auto const digest = sha512Half(Slice{kTag.data(), kTag.size()}, account, issuer, issuanceID);
    auto const randomness = confidential_mpt::reduceScalar(Slice{digest.data(), digest.size()});
    return randomness ? confidential_mpt::encryptZero(publicKey, *randomness) : std::nullopt;
}

}  // namespace xrpl
