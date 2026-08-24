#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/tx/Transactor.h>

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
    // The updated proof document fixes field order but not integer encoding.
    // Use the XRPL convention: unsigned transaction type, sequence/ticket, and
    // version encoded big-endian; account and issuance IDs use canonical bytes.
    std::vector<std::uint8_t> transcript;
    transcript.reserve(
        2 + account.size() + issuanceID.size() + 4 +
        transactionSpecificAccount.size() + 4);
    auto appendU32 = [&](std::uint32_t value) {
        transcript.push_back(static_cast<std::uint8_t>(value >> 24));
        transcript.push_back(static_cast<std::uint8_t>(value >> 16));
        transcript.push_back(static_cast<std::uint8_t>(value >> 8));
        transcript.push_back(static_cast<std::uint8_t>(value));
    };
    transcript.push_back(static_cast<std::uint8_t>(transactionType >> 8));
    transcript.push_back(static_cast<std::uint8_t>(transactionType));
    transcript.insert(transcript.end(), account.begin(), account.end());
    transcript.insert(transcript.end(), issuanceID.begin(), issuanceID.end());
    appendU32(sequenceOrTicket);
    transcript.insert(
        transcript.end(),
        transactionSpecificAccount.begin(),
        transactionSpecificAccount.end());
    appendU32(version);

    auto const id = sha512Half(makeSlice(transcript));
    return {id.begin(), id.end()};
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
