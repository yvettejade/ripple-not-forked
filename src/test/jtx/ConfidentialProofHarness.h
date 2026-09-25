#pragma once

/** Test-only helpers for confidential MPT adversarial proofs (XLS-0096).

    Not a production API. Intentionally small and explicit about whether a
    compact sigma was built for a false statement/context and whether a
    Bulletproof is foreign to the submitted commitments. Prefer these named
    helpers over a deeper abstraction when wiring app-level binding tests.
*/

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/crypto/Bulletproofs.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/UintTypes.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace xrpl {
namespace test {
namespace jtx {
namespace cmpt {

inline constexpr std::size_t kSendZkSize = kSendSigmaSize + kAggregatedBulletproofSize;
inline constexpr std::size_t kConvertBackZkSize = kConvertBackSigmaSize + kSingleBulletproofSize;

/** Named byte offsets into compact sigma prefixes (32-byte limbs). */
struct SigmaOffsets
{
    static constexpr std::size_t kChallenge = 0;
    static constexpr std::size_t kSendZm = 32;
    static constexpr std::size_t kSendZr = 64;
    static constexpr std::size_t kSendZb = 96;
    static constexpr std::size_t kSendZRho = 128;
    static constexpr std::size_t kSendZsk = 160;

    static constexpr std::size_t kConvertBackZb = 32;
    static constexpr std::size_t kConvertBackZRho = 64;
    static constexpr std::size_t kConvertBackZsk = 96;

    static constexpr std::size_t kClawbackZsk = 32;
};

/** Mid-byte of tauX in a single/aggregated BP (A,S,T1,T2 then scalars). */
inline constexpr std::size_t
bpTauXMidOffset()
{
    return 4 * Secp256k1Point::kSerializedSize + Secp256k1Scalar::kSerializedSize / 2;
}

inline std::array<std::uint8_t, 24>
encodeSendTxSpecific(AccountID const& destination, std::uint32_t version)
{
    std::array<std::uint8_t, 24> out{};
    std::memcpy(out.data(), destination.data(), 20);
    out[20] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    out[21] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    out[22] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    out[23] = static_cast<std::uint8_t>(version & 0xff);
    return out;
}

inline std::array<std::uint8_t, 24>
encodeConvertBackTxSpecific(AccountID const& account, std::uint32_t version)
{
    return encodeSendTxSpecific(account, version);
}

inline std::array<std::uint8_t, 24>
encodeClawbackTxSpecific(AccountID const& holder)
{
    std::array<std::uint8_t, 24> out{};
    std::memcpy(out.data(), holder.data(), 20);
    return out;
}

inline std::array<std::uint8_t, 32>
convertContextID(AccountID const& account, MPTID const& issuanceID, std::uint32_t sequence)
{
    return confidentialTxContextID(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT), account, issuanceID, sequence);
}

inline std::array<std::uint8_t, 32>
sendContextID(
    AccountID const& sender,
    MPTID const& issuanceID,
    std::uint32_t sequence,
    AccountID const& destination,
    std::uint32_t version)
{
    auto const specific = encodeSendTxSpecific(destination, version);
    return confidentialTxContextID(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
        sender,
        issuanceID,
        sequence,
        makeSlice(specific));
}

inline std::array<std::uint8_t, 32>
convertBackContextID(
    AccountID const& account,
    MPTID const& issuanceID,
    std::uint32_t sequence,
    std::uint32_t version)
{
    auto const specific = encodeConvertBackTxSpecific(account, version);
    return confidentialTxContextID(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
        account,
        issuanceID,
        sequence,
        makeSlice(specific));
}

inline std::array<std::uint8_t, 32>
clawbackContextID(
    AccountID const& issuer,
    MPTID const& issuanceID,
    std::uint32_t sequence,
    AccountID const& holder)
{
    auto const specific = encodeClawbackTxSpecific(holder);
    return confidentialTxContextID(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
        issuer,
        issuanceID,
        sequence,
        makeSlice(specific));
}

inline std::array<std::uint8_t, kSendZkSize>
spliceSendZk(
    std::array<std::uint8_t, kSendSigmaSize> const& sigma,
    std::array<std::uint8_t, kAggregatedBulletproofSize> const& bp)
{
    std::array<std::uint8_t, kSendZkSize> zk{};
    std::memcpy(zk.data(), sigma.data(), kSendSigmaSize);
    std::memcpy(zk.data() + kSendSigmaSize, bp.data(), kAggregatedBulletproofSize);
    return zk;
}

inline std::array<std::uint8_t, kConvertBackZkSize>
spliceConvertBackZk(
    std::array<std::uint8_t, kConvertBackSigmaSize> const& sigma,
    std::array<std::uint8_t, kSingleBulletproofSize> const& bp)
{
    std::array<std::uint8_t, kConvertBackZkSize> zk{};
    std::memcpy(zk.data(), sigma.data(), kConvertBackSigmaSize);
    std::memcpy(zk.data() + kConvertBackSigmaSize, bp.data(), kSingleBulletproofSize);
    return zk;
}

/** XOR one byte at an absolute offset inside a mutable proof buffer. */
inline void
mutateProofByte(std::span<std::uint8_t> proof, std::size_t offset, std::uint8_t mask = 0x01)
{
    if (offset < proof.size())
        proof[offset] ^= mask;
}

inline void
mutateSendSigmaByte(
    std::array<std::uint8_t, kSendZkSize>& zk,
    std::size_t sigmaOffset,
    std::uint8_t mask = 0x01)
{
    mutateProofByte(zk, sigmaOffset, mask);
}

inline void
mutateSendBpByte(
    std::array<std::uint8_t, kSendZkSize>& zk,
    std::size_t bpOffset,
    std::uint8_t mask = 0x01)
{
    mutateProofByte(zk, kSendSigmaSize + bpOffset, mask);
}

inline void
mutateConvertBackSigmaByte(
    std::array<std::uint8_t, kConvertBackZkSize>& zk,
    std::size_t sigmaOffset,
    std::uint8_t mask = 0x01)
{
    mutateProofByte(zk, sigmaOffset, mask);
}

inline void
mutateConvertBackBpByte(
    std::array<std::uint8_t, kConvertBackZkSize>& zk,
    std::size_t bpOffset,
    std::uint8_t mask = 0x01)
{
    mutateProofByte(zk, kConvertBackSigmaSize + bpOffset, mask);
}

inline void
mutateClawbackByte(
    std::array<std::uint8_t, kClawbackSigmaSize>& proof,
    std::size_t offset,
    std::uint8_t mask = 0x01)
{
    mutateProofByte(proof, offset, mask);
}

/** Result of a foreign single-range BP for commitments other than `commitment`. */
struct ForeignSingleBp
{
    std::array<std::uint8_t, kSingleBulletproofSize> proof{};
    std::optional<Secp256k1Point> foreignCommitment;
    /** Always true: proof verifies for foreignCommitment, not the caller's. */
    bool bulletproofIsForeign = true;
};

/** Prove a valid range BP on an independent commitment (same value, different blind). */
inline std::optional<ForeignSingleBp>
makeForeignSingleBulletproof(std::uint64_t value, Secp256k1Scalar const& foreignBlind)
{
    auto const commitment = pedersenCommit(value, foreignBlind);
    if (!commitment)
        return std::nullopt;
    auto const proof = proveRange64(value, foreignBlind, *commitment);
    if (!proof)
        return std::nullopt;
    ForeignSingleBp out;
    out.proof = *proof;
    out.foreignCommitment = *commitment;
    out.bulletproofIsForeign = true;
    return out;
}

struct ForeignAggregatedBp
{
    std::array<std::uint8_t, kAggregatedBulletproofSize> proof{};
    std::optional<Secp256k1Point> foreignPcM;
    std::optional<Secp256k1Point> foreignPcRem;
    bool bulletproofIsForeign = true;
};

inline std::optional<ForeignAggregatedBp>
makeForeignAggregatedBulletproof(
    std::uint64_t amount,
    Secp256k1Scalar const& foreignAmountBlind,
    std::uint64_t rem,
    Secp256k1Scalar const& foreignRemBlind)
{
    auto const pcM = pedersenCommit(amount, foreignAmountBlind);
    auto const pcRem = pedersenCommit(rem, foreignRemBlind);
    if (!pcM || !pcRem)
        return std::nullopt;
    auto const proof =
        proveRange64Aggregated(amount, foreignAmountBlind, *pcM, rem, foreignRemBlind, *pcRem);
    if (!proof)
        return std::nullopt;
    ForeignAggregatedBp out;
    out.proof = *proof;
    out.foreignPcM = *pcM;
    out.foreignPcRem = *pcRem;
    out.bulletproofIsForeign = true;
    return out;
}

/** Annotated Send ZK bundle so call sites state verifier-split intent. */
struct AnnotatedSendZk
{
    std::array<std::uint8_t, kSendZkSize> bytes{};
    /** True when proveSendSigma succeeded for the (possibly false) statement/context. */
    bool sigmaValidForBuiltStatement = false;
    /** True when the BP openings are not the submitted pcM / (pcB-pcM). */
    bool bulletproofIsForeign = false;
};

inline std::optional<AnnotatedSendZk>
annotateSendZk(
    std::array<std::uint8_t, kSendSigmaSize> const& sigma,
    std::array<std::uint8_t, kAggregatedBulletproofSize> const& bp,
    bool sigmaValidForBuiltStatement,
    bool bulletproofIsForeign)
{
    AnnotatedSendZk out;
    out.bytes = spliceSendZk(sigma, bp);
    out.sigmaValidForBuiltStatement = sigmaValidForBuiltStatement;
    out.bulletproofIsForeign = bulletproofIsForeign;
    return out;
}

struct AnnotatedConvertBackZk
{
    std::array<std::uint8_t, kConvertBackZkSize> bytes{};
    bool sigmaValidForBuiltStatement = false;
    bool bulletproofIsForeign = false;
};

inline std::optional<AnnotatedConvertBackZk>
annotateConvertBackZk(
    std::array<std::uint8_t, kConvertBackSigmaSize> const& sigma,
    std::array<std::uint8_t, kSingleBulletproofSize> const& bp,
    bool sigmaValidForBuiltStatement,
    bool bulletproofIsForeign)
{
    AnnotatedConvertBackZk out;
    out.bytes = spliceConvertBackZk(sigma, bp);
    out.sigmaValidForBuiltStatement = sigmaValidForBuiltStatement;
    out.bulletproofIsForeign = bulletproofIsForeign;
    return out;
}

inline std::string
hexOf(Slice data)
{
    return strHex(data);
}

template <std::size_t N>
inline std::string
hexOf(std::array<std::uint8_t, N> const& data)
{
    return strHex(makeSlice(data));
}

}  // namespace cmpt
}  // namespace jtx
}  // namespace test
}  // namespace xrpl
