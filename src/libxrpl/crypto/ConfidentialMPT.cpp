#include <xrpl/crypto/ConfidentialMPT.h>

#include <secp256k1.h>
#include <secp256k1_mpt.h>
#include <utility/mpt_utility.h>

#include <array>

namespace xrpl::confidential {
namespace {

bool
parsePublicKey(Slice value, secp256k1_pubkey& result)
{
    return value.size() == publicKeySize &&
        secp256k1_ec_pubkey_parse(
               mpt_secp256k1_context(), &result, value.data(), value.size()) == 1;
}

bool
parseCiphertext(Slice value, secp256k1_pubkey& c1, secp256k1_pubkey& c2)
{
    return value.size() == ciphertextSize && mpt_make_ec_pair(value.data(), &c1, &c2);
}

std::optional<Blob>
combineCiphertexts(Slice lhs, Slice rhs, bool subtract)
{
    secp256k1_pubkey lhsC1;
    secp256k1_pubkey lhsC2;
    secp256k1_pubkey rhsC1;
    secp256k1_pubkey rhsC2;
    if (!parseCiphertext(lhs, lhsC1, lhsC2) || !parseCiphertext(rhs, rhsC1, rhsC2))
        return std::nullopt;

    secp256k1_pubkey resultC1;
    secp256k1_pubkey resultC2;
    auto const success = subtract
        ? secp256k1_elgamal_subtract(
              mpt_secp256k1_context(),
              &resultC1,
              &resultC2,
              &lhsC1,
              &lhsC2,
              &rhsC1,
              &rhsC2)
        : secp256k1_elgamal_add(
              mpt_secp256k1_context(),
              &resultC1,
              &resultC2,
              &lhsC1,
              &lhsC2,
              &rhsC1,
              &rhsC2);
    if (success != 1)
        return std::nullopt;

    Blob result(ciphertextSize);
    if (!mpt_serialize_ec_pair(&resultC1, &resultC2, result.data()))
        return std::nullopt;
    return result;
}

}  // namespace

bool
isValidPublicKey(Slice value)
{
    secp256k1_pubkey key;
    return parsePublicKey(value, key);
}

bool
isValidCiphertext(Slice value)
{
    secp256k1_pubkey c1;
    secp256k1_pubkey c2;
    return parseCiphertext(value, c1, c2);
}

std::optional<Blob>
addCiphertexts(Slice lhs, Slice rhs)
{
    return combineCiphertexts(lhs, rhs, false);
}

std::optional<Blob>
subtractCiphertexts(Slice lhs, Slice rhs)
{
    return combineCiphertexts(lhs, rhs, true);
}

std::optional<Blob>
canonicalEncryptedZero(
    AccountID const& account,
    MPTID const& issuanceID,
    Slice publicKey)
{
    secp256k1_pubkey key;
    if (!parsePublicKey(publicKey, key))
        return std::nullopt;

    secp256k1_pubkey c1;
    secp256k1_pubkey c2;
    if (generate_canonical_encrypted_zero(
            mpt_secp256k1_context(),
            &c1,
            &c2,
            &key,
            account.data(),
            issuanceID.data()) != 1)
        return std::nullopt;

    Blob result(ciphertextSize);
    if (!mpt_serialize_ec_pair(&c1, &c2, result.data()))
        return std::nullopt;
    return result;
}

}  // namespace xrpl::confidential
