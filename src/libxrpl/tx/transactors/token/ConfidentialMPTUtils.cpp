#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/STTx.h>
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
    std::uint32_t version)
{
    // XLS-0096 requires domain binding but did not define byte order or replace
    // its non-MPT Currency element. This was raised; big-endian type, account,
    // issuance ID, and version are used.
    std::vector<std::uint8_t> out;
    out.reserve(2 + account.size() + issuanceID.size() + 4);
    out.push_back(static_cast<std::uint8_t>(transactionType >> 8));
    out.push_back(static_cast<std::uint8_t>(transactionType));
    out.insert(out.end(), account.begin(), account.end());
    out.insert(out.end(), issuanceID.begin(), issuanceID.end());
    out.push_back(static_cast<std::uint8_t>(version >> 24));
    out.push_back(static_cast<std::uint8_t>(version >> 16));
    out.push_back(static_cast<std::uint8_t>(version >> 8));
    out.push_back(static_cast<std::uint8_t>(version));
    return out;
}

}  // namespace xrpl::confidential_mpt
