#include <xrpl/tx/transactors/token/ConfidentialMPTHelpers.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <initializer_list>
#include <optional>

namespace xrpl::confidential_mpt {

using namespace confidential;

XRPAmount
baseFee(ReadView const& view, STTx const& tx)
{
    return Transactor::calculateBaseFee(view, tx) * kFeeMultiplier;
}

// An absent field reads as an empty blob, which neither parser accepts.
std::optional<ElGamalCiphertext>
ciphertext(STObject const& object, SF_VL const& field)
{
    return ElGamalCiphertext::fromBytes(makeSlice(object.getFieldVL(field)));
}

std::optional<Point>
point(STObject const& object, SF_VL const& field)
{
    return Point::fromBytes(makeSlice(object.getFieldVL(field)));
}

std::optional<Scalar>
blindingFactor(STTx const& tx)
{
    auto const bf = tx[sfBlindingFactor];
    return Scalar::fromBytes(Slice(bf.data(), bf.size()));
}

NotTEC
checkCiphertexts(STTx const& tx, std::initializer_list<SF_VL const*> fields)
{
    for (auto const* field : fields)
    {
        if (tx.isFieldPresent(*field) && !ciphertext(tx, *field))
            return temBAD_CIPHERTEXT;
    }
    return tesSUCCESS;
}

uint256
contextID(STTx const& tx, AccountID const& party, std::uint32_t version)
{
    return transactionContextID(
        static_cast<std::uint16_t>(tx.getTxnType()),
        tx[sfAccount],
        tx[sfMPTokenIssuanceID],
        tx.getSeqValue(),
        party,
        version);
}

std::optional<IssuanceKeys>
issuanceKeys(SLE const& issuance)
{
    auto const issuer = point(issuance, sfIssuerEncryptionKey);
    if (!issuer)
        return std::nullopt;
    return IssuanceKeys{.issuer = *issuer, .auditor = point(issuance, sfAuditorEncryptionKey)};
}

bool
isInitialized(SLE const& mptoken)
{
    return mptoken.isFieldPresent(sfHolderEncryptionKey) &&
        mptoken.isFieldPresent(sfConfidentialBalanceSpending) &&
        mptoken.isFieldPresent(sfConfidentialBalanceInbox) &&
        mptoken.isFieldPresent(sfIssuerEncryptedBalance);
}

TER
checkAuditorPolicy(STTx const& tx, IssuanceKeys const& keys)
{
    if (keys.auditor.has_value() != tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;
    return tesSUCCESS;
}

TER
store(SLE& sle, SF_VL const& field, ElGamalCiphertext const& ct)
{
    auto const buf = ct.toBuffer();
    if (!buf)
        return tecBAD_PROOF;
    sle.setFieldVL(field, *buf);
    return tesSUCCESS;
}

}  // namespace xrpl::confidential_mpt
