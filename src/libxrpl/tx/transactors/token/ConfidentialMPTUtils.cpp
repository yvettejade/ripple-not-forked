#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/tx/Transactor.h>

#include <utility/mpt_utility.h>

#include <algorithm>
#include <limits>

namespace xrpl::confidential_mpt {

namespace {

using namespace crypto::confidential;

Slice
slice(AccountID const& value)
{
    return {value.data(), value.size()};
}

Slice
slice(MPTID const& value)
{
    return {value.data(), value.size()};
}

}  // namespace

XRPAmount
proofBaseFee(ReadView const& view, STTx const& tx)
{
    auto const normal = Transactor::calculateBaseFee(view, tx);
    // XLS-0096 described the 10x fee as reference behavior without defining
    // whether it was normative. This was raised and clarified as consensus-enforced.
    return normal * 10;
}

bool
validPoint(Slice blob)
{
    CompressedPoint point;
    return parseCompressedPoint(blob, point);
}

bool
validCiphertext(Slice blob)
{
    Ciphertext ciphertext;
    return parseCiphertext(blob, ciphertext);
}

std::optional<Blob>
addCiphertexts(Slice lhs, Slice rhs)
{
    Ciphertext left;
    Ciphertext right;
    Ciphertext sum;
    CiphertextBlob serialized;
    if (!parseCiphertext(lhs, left) || !parseCiphertext(rhs, right) ||
        !ciphertextAdd(left, right, sum) || !serializeCiphertext(sum, serialized))
        return std::nullopt;
    return Blob{serialized.begin(), serialized.end()};
}

std::optional<Blob>
subtractCiphertexts(Slice lhs, Slice rhs)
{
    Ciphertext left;
    Ciphertext right;
    Ciphertext difference;
    CiphertextBlob serialized;
    if (!parseCiphertext(lhs, left) || !parseCiphertext(rhs, right) ||
        !ciphertextSub(left, right, difference) ||
        !serializeCiphertext(difference, serialized))
        return std::nullopt;
    return Blob{serialized.begin(), serialized.end()};
}

std::optional<Blob>
canonicalZero(
    AccountID const& account,
    MPTID const& issuanceID,
    Slice publicKey)
{
    CompressedPoint key;
    Ciphertext zero;
    CiphertextBlob serialized;
    if (!parseCompressedPoint(publicKey, key) ||
        !canonicalEncryptedZero(slice(account), slice(issuanceID), key, zero) ||
        !serializeCiphertext(zero, serialized))
        return std::nullopt;
    return Blob{serialized.begin(), serialized.end()};
}

std::vector<std::uint8_t>
proofContext(
    std::uint16_t transactionType,
    AccountID const& account,
    MPTID const& issuanceID,
    std::uint32_t sequenceOrTicket,
    AccountID const& transactionSpecificAccount,
    std::uint32_t version)
{
    account_id accountBytes{};
    account_id specificAccountBytes{};
    mpt_issuance_id issuanceBytes{};
    std::copy(account.begin(), account.end(), accountBytes.bytes);
    std::copy(
        transactionSpecificAccount.begin(),
        transactionSpecificAccount.end(),
        specificAccountBytes.bytes);
    std::copy(issuanceID.begin(), issuanceID.end(), issuanceBytes.bytes);

    std::vector<std::uint8_t> context(kMPT_HALF_SHA_SIZE);
    int result = -1;
    switch (transactionType)
    {
        case ttCONFIDENTIAL_MPT_CONVERT:
            result = mpt_get_convert_context_hash(
                accountBytes,
                issuanceBytes,
                sequenceOrTicket,
                context.data());
            break;
        case ttCONFIDENTIAL_MPT_CONVERT_BACK:
            result = mpt_get_convert_back_context_hash(
                accountBytes,
                issuanceBytes,
                sequenceOrTicket,
                version,
                context.data());
            break;
        case ttCONFIDENTIAL_MPT_SEND:
            result = mpt_get_send_context_hash(
                accountBytes,
                issuanceBytes,
                sequenceOrTicket,
                specificAccountBytes,
                version,
                context.data());
            break;
        case ttCONFIDENTIAL_MPT_CLAWBACK:
            result = mpt_get_clawback_context_hash(
                accountBytes,
                issuanceBytes,
                sequenceOrTicket,
                specificAccountBytes,
                context.data());
            break;
        default:
            break;
    }
    if (result != 0)
        return {};
    return context;
}

std::vector<std::uint8_t>
proofContext(
    STTx const& tx,
    AccountID const& transactionSpecificAccount,
    std::uint32_t version)
{
    return proofContext(
        static_cast<std::uint16_t>(tx.getTxnType()),
        tx[sfAccount],
        tx[sfMPTokenIssuanceID],
        tx.getSeqValue(),
        transactionSpecificAccount,
        version);
}

void
setConfidentialOutstanding(STLedgerEntry& issuance, std::uint64_t amount)
{
    // sfConfidentialOutstandingAmount is a defaulted UINT64. Writing 0 throws.
    if (amount == 0)
        issuance.makeFieldAbsent(sfConfidentialOutstandingAmount);
    else
        issuance.setFieldU64(sfConfidentialOutstandingAmount, amount);
}

}  // namespace xrpl::confidential_mpt
