#include <xrpl/crypto/confidential/Proofs.h>

#include <libxrpl/crypto/confidential/Detail.h>

#include <cstring>

namespace xrpl {
namespace crypto {
namespace confidential {
namespace {

bool
parseProof(SchnorrProof const& proof, Scalar& c, Scalar& z) noexcept
{
    if (!parseNonZeroScalar(Slice(proof.data(), 32), c))
        return false;
    if (!parseNonZeroScalar(Slice(proof.data() + 32, 32), z))
        return false;
    return true;
}

void
writeProof(Scalar const& c, Scalar const& z, SchnorrProof& proof) noexcept
{
    std::memcpy(proof.data(), c.data(), 32);
    std::memcpy(proof.data() + 32, z.data(), 32);
}

/** Sample a non-zero scalar from SHA512-Half(seed parts), reduced mod n.
 * Retries with a counter byte if the result is zero (negligible).
 *
 * XLS-0096 left nonce derivation for provers unspecified; this is only used
 * by create* helpers for tests and must match no on-ledger requirement.
 */
bool
deriveNonce(Scalar& out, Slice a, Slice b, Slice c = {}) noexcept
{
    for (std::uint8_t i = 0; i < 8; ++i)
    {
        std::uint8_t hash[32];
        std::uint8_t ctr[1] = {i};
        detail::sha512HalfParts(
            hash, a, b, c, Slice(ctr, 1), Slice("CMT/nonce", 9));
        if (detail::scalarReduceModOrder(hash, out) && !scalarIsZero(out))
            return true;
    }
    return false;
}

bool
challengeSchnorr(
    CompressedPoint const& pk,
    CompressedPoint const& R,
    Slice extra,
    Scalar& cOut) noexcept
{
    static constexpr char const kDomain[] = "CMT/SchnorrPoK";
    std::uint8_t hash[32];
    detail::sha512HalfParts(
        hash,
        Slice(kDomain, sizeof(kDomain) - 1),
        Slice(pk.data(), pk.size()),
        Slice(R.data(), R.size()),
        extra);
    return detail::scalarReduceModOrder(hash, cOut) && !scalarIsZero(cOut);
}

bool
challengeClawback(
    CompressedPoint const& pk,
    CompressedPoint const& R,
    CompressedPoint const& S,
    std::uint64_t m,
    CompressedPoint const& A1,
    CompressedPoint const& A2,
    Slice extra,
    Scalar& cOut) noexcept
{
    static constexpr char const kDomain[] = "CMT/Clawback";
    std::uint8_t mBe[8];
    detail::writeUint64BE(m, mBe);
    std::uint8_t hash[32];
    detail::sha512HalfParts(
        hash,
        Slice(kDomain, sizeof(kDomain) - 1),
        Slice(pk.data(), pk.size()),
        Slice(R.data(), R.size()),
        Slice(S.data(), S.size()),
        Slice(mBe, sizeof(mBe)),
        Slice(A1.data(), A1.size()),
        Slice(A2.data(), A2.size()),
        extra);
    return detail::scalarReduceModOrder(hash, cOut) && !scalarIsZero(cOut);
}

}  // namespace

bool
verifySchnorrProofOfKnowledge(
    CompressedPoint const& pk,
    SchnorrProof const& proof,
    Slice extra) noexcept
{
    CompressedPoint pkCanon;
    if (!parseCompressedPoint(Slice(pk.data(), pk.size()), pkCanon))
        return false;

    Scalar c;
    Scalar z;
    if (!parseProof(proof, c, z))
        return false;

    secp256k1_pubkey Y;
    secp256k1_pubkey zG;
    secp256k1_pubkey cY;
    if (!detail::parsePubkey(pkCanon, Y) || !detail::pointMulG(z, zG) ||
        !detail::pointMul(Y, c, cY))
        return false;

    // R = zG - cY
    secp256k1_pubkey Rpk;
    if (!detail::pointSub(zG, cY, Rpk))
        return false;

    CompressedPoint R;
    if (!detail::serializePubkey(Rpk, R))
        return false;

    Scalar cPrime;
    if (!challengeSchnorr(pkCanon, R, extra, cPrime))
        return false;
    return c == cPrime;
}

bool
createSchnorrProofOfKnowledge(
    Scalar const& x,
    CompressedPoint const& pk,
    SchnorrProof& proof,
    Slice extra) noexcept
{
    Scalar xCanon;
    if (!parseNonZeroScalar(Slice(x.data(), x.size()), xCanon))
        return false;

    CompressedPoint pkCanon;
    if (!parseCompressedPoint(Slice(pk.data(), pk.size()), pkCanon))
        return false;

    // Sanity: pk must equal x·G
    secp256k1_pubkey expect;
    CompressedPoint expectBytes;
    if (!detail::pointMulG(xCanon, expect) ||
        !detail::serializePubkey(expect, expectBytes) || expectBytes != pkCanon)
        return false;

    Scalar k;
    if (!deriveNonce(k, Slice(xCanon.data(), 32), Slice(pkCanon.data(), 33), extra))
        return false;

    secp256k1_pubkey Rpk;
    CompressedPoint R;
    if (!detail::pointMulG(k, Rpk) || !detail::serializePubkey(Rpk, R))
        return false;

    Scalar c;
    if (!challengeSchnorr(pkCanon, R, extra, c))
        return false;

    // z = k + c·x  (mod n)
    Scalar cx;
    Scalar z;
    if (!scalarMul(c, xCanon, cx) || !scalarAdd(k, cx, z) || scalarIsZero(z))
        return false;

    writeProof(c, z, proof);
    return true;
}

bool
verifyClawbackProof(
    CompressedPoint const& issuerPk,
    Ciphertext const& issuerCiphertext,
    std::uint64_t m,
    SchnorrProof const& proof,
    Slice extra) noexcept
{
    CompressedPoint pkCanon;
    CompressedPoint Rcanon;
    CompressedPoint Scanon;
    if (!parseCompressedPoint(Slice(issuerPk.data(), issuerPk.size()), pkCanon) ||
        !parseCompressedPoint(
            Slice(issuerCiphertext.R.data(), issuerCiphertext.R.size()), Rcanon) ||
        !parseCompressedPoint(
            Slice(issuerCiphertext.S.data(), issuerCiphertext.S.size()), Scanon))
        return false;

    Scalar c;
    Scalar z;
    if (!parseProof(proof, c, z))
        return false;

    secp256k1_pubkey Y;
    secp256k1_pubkey R;
    secp256k1_pubkey S;
    if (!detail::parsePubkey(pkCanon, Y) || !detail::parsePubkey(Rcanon, R) ||
        !detail::parsePubkey(Scanon, S))
        return false;

    // T = S - m·G
    secp256k1_pubkey T = S;
    if (m != 0)
    {
        secp256k1_pubkey mG;
        if (!detail::pointMulGUint64(m, mG))
            return false;
        if (!detail::pointSub(S, mG, T))
            return false;
    }

    // A1 = z·G - c·Y
    secp256k1_pubkey zG;
    secp256k1_pubkey cY;
    secp256k1_pubkey A1pk;
    if (!detail::pointMulG(z, zG) || !detail::pointMul(Y, c, cY) ||
        !detail::pointSub(zG, cY, A1pk))
        return false;

    // A2 = z·R - c·T
    secp256k1_pubkey zR;
    secp256k1_pubkey cT;
    secp256k1_pubkey A2pk;
    if (!detail::pointMul(R, z, zR) || !detail::pointMul(T, c, cT) ||
        !detail::pointSub(zR, cT, A2pk))
        return false;

    CompressedPoint A1;
    CompressedPoint A2;
    if (!detail::serializePubkey(A1pk, A1) || !detail::serializePubkey(A2pk, A2))
        return false;

    Scalar cPrime;
    if (!challengeClawback(pkCanon, Rcanon, Scanon, m, A1, A2, extra, cPrime))
        return false;
    return c == cPrime;
}

bool
createClawbackProof(
    Scalar const& issuerSecret,
    CompressedPoint const& issuerPk,
    Ciphertext const& issuerCiphertext,
    std::uint64_t m,
    SchnorrProof& proof,
    Slice extra) noexcept
{
    Scalar x;
    if (!parseNonZeroScalar(Slice(issuerSecret.data(), issuerSecret.size()), x))
        return false;

    CompressedPoint pkCanon;
    CompressedPoint Rcanon;
    CompressedPoint Scanon;
    if (!parseCompressedPoint(Slice(issuerPk.data(), issuerPk.size()), pkCanon) ||
        !parseCompressedPoint(
            Slice(issuerCiphertext.R.data(), issuerCiphertext.R.size()), Rcanon) ||
        !parseCompressedPoint(
            Slice(issuerCiphertext.S.data(), issuerCiphertext.S.size()), Scanon))
        return false;

    secp256k1_pubkey expect;
    CompressedPoint expectBytes;
    if (!detail::pointMulG(x, expect) ||
        !detail::serializePubkey(expect, expectBytes) || expectBytes != pkCanon)
        return false;

    // Check ciphertext relation: S - mG == x·R
    {
        secp256k1_pubkey R;
        secp256k1_pubkey S;
        secp256k1_pubkey xR;
        if (!detail::parsePubkey(Rcanon, R) || !detail::parsePubkey(Scanon, S) ||
            !detail::pointMul(R, x, xR))
            return false;
        secp256k1_pubkey T = S;
        if (m != 0)
        {
            secp256k1_pubkey mG;
            if (!detail::pointMulGUint64(m, mG) || !detail::pointSub(S, mG, T))
                return false;
        }
        CompressedPoint tBytes;
        CompressedPoint xRBytes;
        if (!detail::serializePubkey(T, tBytes) ||
            !detail::serializePubkey(xR, xRBytes) || tBytes != xRBytes)
            return false;
    }

    Scalar k;
    if (!deriveNonce(
            k,
            Slice(x.data(), 32),
            Slice(Rcanon.data(), 33),
            Slice(Scanon.data(), 33)))
        return false;

    secp256k1_pubkey R;
    if (!detail::parsePubkey(Rcanon, R))
        return false;

    // A1 = k·G, A2 = k·R
    secp256k1_pubkey A1pk;
    secp256k1_pubkey A2pk;
    CompressedPoint A1;
    CompressedPoint A2;
    if (!detail::pointMulG(k, A1pk) || !detail::pointMul(R, k, A2pk) ||
        !detail::serializePubkey(A1pk, A1) || !detail::serializePubkey(A2pk, A2))
        return false;

    Scalar c;
    if (!challengeClawback(pkCanon, Rcanon, Scanon, m, A1, A2, extra, c))
        return false;

    Scalar cx;
    Scalar z;
    if (!scalarMul(c, x, cx) || !scalarAdd(k, cx, z) || scalarIsZero(z))
        return false;

    writeProof(c, z, proof);
    return true;
}

}  // namespace confidential
}  // namespace crypto
}  // namespace xrpl
