#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/protocol/digest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

namespace xrpl {
namespace {

constexpr std::string_view kEncZeroTag = "EncZero";

void
writeUint16BE(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[1] = static_cast<std::uint8_t>(value & 0xff);
}

void
writeUint32BE(std::uint8_t* out, std::uint32_t value)
{
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xff);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[3] = static_cast<std::uint8_t>(value & 0xff);
}

[[nodiscard]] Blob
serializeCiphertext(ElGamalCiphertext const& ct)
{
    auto const bytes = ct.serialize();
    return Blob(bytes.begin(), bytes.end());
}

}  // namespace

std::optional<ElGamalCiphertext>
parseElGamalCiphertext(Slice data)
{
    return ElGamalCiphertext::parse(data);
}

NotTEC
validateElGamalCiphertext(Slice data)
{
    if (!ElGamalCiphertext::parse(data))
        return temBAD_CIPHERTEXT;
    return tesSUCCESS;
}

std::optional<Blob>
homomorphicAddCiphertexts(Slice left, Slice right)
{
    auto const a = ElGamalCiphertext::parse(left);
    if (!a)
        return std::nullopt;
    auto const b = ElGamalCiphertext::parse(right);
    if (!b)
        return std::nullopt;
    auto const sum = a->add(*b);
    if (!sum)
        return std::nullopt;
    return serializeCiphertext(*sum);
}

std::optional<Blob>
homomorphicSubCiphertexts(Slice left, Slice right)
{
    auto const a = ElGamalCiphertext::parse(left);
    if (!a)
        return std::nullopt;
    auto const b = ElGamalCiphertext::parse(right);
    if (!b)
        return std::nullopt;
    auto const diff = a->subtract(*b);
    if (!diff)
        return std::nullopt;
    return serializeCiphertext(*diff);
}

bool
verifyPlaintextElGamal(
    ElGamalCiphertext const& ciphertext,
    std::uint64_t amount,
    Secp256k1Point const& publicKey,
    Secp256k1Scalar const& randomness)
{
    auto const expected = ElGamalCiphertext::encrypt(amount, publicKey, randomness);
    if (!expected)
        return false;  // LCOV_EXCL_LINE
    return *expected == ciphertext;
}

std::optional<Blob>
encZero(
    AccountID const& account,
    AccountID const& issuer,
    MPTID const& issuanceID,
    Secp256k1Point const& publicKey)
{
    // Spec gap: H("EncZero"||...) is unnamed; use hashToCurveScalar (SHA-512).
    std::vector<std::uint8_t> msg;
    msg.reserve(kEncZeroTag.size() + AccountID::kBytes + AccountID::kBytes + MPTID::kBytes);
    msg.insert(msg.end(), kEncZeroTag.begin(), kEncZeroTag.end());
    msg.insert(msg.end(), account.data(), account.data() + AccountID::kBytes);
    msg.insert(msg.end(), issuer.data(), issuer.data() + AccountID::kBytes);
    msg.insert(msg.end(), issuanceID.data(), issuanceID.data() + MPTID::kBytes);

    auto const r = hashToCurveScalar(makeSlice(msg));
    if (!r)
        return std::nullopt;  // LCOV_EXCL_LINE

    // EncZero = Enc(0, pk, r) = (r·G, r·Pk)
    auto const ct = ElGamalCiphertext::encrypt(0, publicKey, *r);
    if (!ct)
        return std::nullopt;  // LCOV_EXCL_LINE
    return serializeCiphertext(*ct);
}

std::array<std::uint8_t, 32>
confidentialTxContextID(
    std::uint16_t txType,
    AccountID const& account,
    MPTID const& issuanceID,
    std::uint32_t sequenceOrTicket,
    Slice txSpecific)
{
    std::vector<std::uint8_t> msg(2 + AccountID::kBytes + MPTID::kBytes + 4 + txSpecific.size());
    writeUint16BE(msg.data(), txType);
    std::memcpy(msg.data() + 2, account.data(), AccountID::kBytes);
    std::memcpy(msg.data() + 2 + AccountID::kBytes, issuanceID.data(), MPTID::kBytes);
    writeUint32BE(msg.data() + 2 + AccountID::kBytes + MPTID::kBytes, sequenceOrTicket);
    if (!txSpecific.empty())
    {
        std::memcpy(
            msg.data() + 2 + AccountID::kBytes + MPTID::kBytes + 4,
            txSpecific.data(),
            txSpecific.size());
    }

    auto const digest = sha512Half(makeSlice(msg));
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), digest.data(), out.size());
    return out;
}

}  // namespace xrpl
