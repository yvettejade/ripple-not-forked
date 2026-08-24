#include <xrpl/crypto/confidential/Proofs.h>

#include <libxrpl/crypto/confidential/Detail.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <string_view>

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

template <std::size_t N, std::size_t Bytes>
bool
parseScalars(
    std::array<std::uint8_t, Bytes> const& proof,
    std::array<Scalar, N>& scalars) noexcept
{
    static_assert(Bytes == N * kScalarBytes);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!parseNonZeroScalar(
                Slice(proof.data() + i * kScalarBytes, kScalarBytes),
                scalars[i]))
            return false;
    }
    return true;
}

template <std::size_t N, std::size_t Bytes>
void
writeScalars(
    std::array<Scalar, N> const& scalars,
    std::array<std::uint8_t, Bytes>& proof) noexcept
{
    static_assert(Bytes == N * kScalarBytes);
    for (std::size_t i = 0; i < N; ++i)
        std::memcpy(
            proof.data() + i * kScalarBytes, scalars[i].data(), kScalarBytes);
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
deriveNonce(
    Scalar& out,
    Slice witness,
    Slice context,
    std::string_view label) noexcept
{
    return deriveNonce(
        out,
        witness,
        context,
        Slice(label.data(), label.size()));
}

bool
parsePoint(CompressedPoint const& bytes, secp256k1_pubkey& point) noexcept
{
    CompressedPoint canonical;
    return parseCompressedPoint(makeSlice(bytes), canonical) &&
        detail::parsePubkey(canonical, point);
}

bool
linearCombination(
    Scalar const& gScalar,
    secp256k1_pubkey const& point,
    Scalar const& pointScalar,
    secp256k1_pubkey& out) noexcept
{
    secp256k1_pubkey g;
    secp256k1_pubkey p;
    return detail::pointMulG(gScalar, g) &&
        detail::pointMul(point, pointScalar, p) && detail::pointAdd(g, p, out);
}

bool
subtractMultiple(
    secp256k1_pubkey const& value,
    secp256k1_pubkey const& point,
    Scalar const& scalar,
    secp256k1_pubkey& out) noexcept
{
    secp256k1_pubkey multiple;
    return detail::pointMul(point, scalar, multiple) &&
        detail::pointSub(value, multiple, out);
}

bool
serialize(secp256k1_pubkey const& point, CompressedPoint& out) noexcept
{
    return detail::serializePubkey(point, out);
}

class ChallengeHash
{
    SHA512_CTX ctx_;

public:
    explicit ChallengeHash(std::string_view domain) noexcept
    {
        SHA512_Init(&ctx_);
        add(Slice(domain.data(), domain.size()));
    }

    void
    add(Slice value) noexcept
    {
        if (!value.empty())
            SHA512_Update(&ctx_, value.data(), value.size());
    }

    void
    add(CompressedPoint const& point) noexcept
    {
        add(makeSlice(point));
    }

    bool
    finish(Scalar& out) noexcept
    {
        std::uint8_t digest[SHA512_DIGEST_LENGTH];
        SHA512_Final(digest, &ctx_);
        bool const ok =
            detail::scalarReduceModOrder(digest, out) && !scalarIsZero(out);
        secureErase(digest, sizeof(digest));
        return ok;
    }
};

bool
constantTimeEqual(Scalar const& lhs, Scalar const& rhs) noexcept
{
    return CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

bool
challengeSend(
    SendSigmaStatement const& statement,
    std::vector<CompressedPoint> const& t2,
    CompressedPoint const& t1,
    CompressedPoint const& tm,
    CompressedPoint const& tb,
    CompressedPoint const& tsk1,
    CompressedPoint const& tsk2,
    Slice context,
    Scalar& out) noexcept
{
    ChallengeHash hash("CMPT_SEND_SIGMA");
    for (auto const& key : statement.recipientPublicKeys)
        hash.add(key);
    hash.add(statement.senderPublicKey);
    hash.add(statement.sharedCiphertext);
    for (auto const& encrypted : statement.encryptedAmounts)
        hash.add(encrypted);
    hash.add(statement.amountCommitment);
    hash.add(statement.balanceCommitment);
    hash.add(statement.balanceCiphertext.R);
    hash.add(statement.balanceCiphertext.S);
    hash.add(t1);
    for (auto const& commitment : t2)
        hash.add(commitment);
    hash.add(tm);
    hash.add(tb);
    hash.add(tsk1);
    hash.add(tsk2);
    hash.add(context);
    return hash.finish(out);
}

bool
challengeBalance(
    BalanceSigmaStatement const& statement,
    CompressedPoint const& tsk1,
    CompressedPoint const& tsk2,
    CompressedPoint const& tb,
    Slice context,
    Scalar& out) noexcept
{
    ChallengeHash hash("CMPT_CONVERTBACK_SIGMA");
    hash.add(statement.senderPublicKey);
    hash.add(statement.balanceCiphertext.R);
    hash.add(statement.balanceCiphertext.S);
    hash.add(statement.balanceCommitment);
    hash.add(tsk1);
    hash.add(tsk2);
    hash.add(tb);
    hash.add(context);
    return hash.finish(out);
}

bool
challengeSchnorr(
    CompressedPoint const& pk,
    CompressedPoint const& R,
    Slice extra,
    Scalar& cOut) noexcept
{
    ChallengeHash hash("CMPT_POK_SK_REGISTER");
    hash.add(pk);
    hash.add(R);
    hash.add(extra);
    return hash.finish(cOut);
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
    if (m == 0)
        return false;
    secp256k1_pubkey mGPoint;
    CompressedPoint mG;
    if (!detail::pointMulGUint64(m, mGPoint) || !serialize(mGPoint, mG))
        return false;
    ChallengeHash hash("CMPT_CLAWBACK_SIGMA");
    hash.add(pk);
    hash.add(R);
    hash.add(S);
    hash.add(mG);
    hash.add(A1);
    hash.add(A2);
    hash.add(extra);
    return hash.finish(cOut);
}

}  // namespace

CompressedPoint const&
pedersenGenerator() noexcept
{
    // libsecp256k1-zkp's standard generator H: SHA256 of the uncompressed
    // DER encoding of secp256k1 G, lifted to the curve.
    static constexpr CompressedPoint h{
        0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
        0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
        0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
    return h;
}

bool
pedersenCommit(
    Scalar const& value,
    Scalar const& blinding,
    CompressedPoint& commitment) noexcept
{
    Scalar valueCanonical;
    Scalar blindingCanonical;
    secp256k1_pubkey h;
    secp256k1_pubkey result;
    if (!parseScalar(makeSlice(value), valueCanonical) ||
        !parseNonZeroScalar(makeSlice(blinding), blindingCanonical) ||
        !parsePoint(pedersenGenerator(), h))
        return false;

    if (scalarIsZero(valueCanonical))
    {
        if (!detail::pointMul(h, blindingCanonical, result))
            return false;
    }
    else if (!linearCombination(valueCanonical, h, blindingCanonical, result))
        return false;
    return serialize(result, commitment);
}

bool
verifySendSigmaProof(
    SendSigmaStatement const& statement,
    SendSigmaProof const& proof,
    Slice transactionContextID,
    Scalar* challenge) noexcept
{
    if (statement.recipientPublicKeys.empty() ||
        statement.recipientPublicKeys.size() !=
            statement.encryptedAmounts.size() ||
        transactionContextID.size() != 32)
        return false;

    std::array<Scalar, 6> scalars;
    if (!parseScalars(proof, scalars))
        return false;
    auto const& [e, zm, zr, zb, zrho, zsk] = scalars;

    secp256k1_pubkey c1;
    secp256k1_pubkey h;
    secp256k1_pubkey pcm;
    secp256k1_pubkey pcb;
    secp256k1_pubkey pa;
    secp256k1_pubkey b1;
    secp256k1_pubkey b2;
    if (!parsePoint(statement.sharedCiphertext, c1) ||
        !parsePoint(pedersenGenerator(), h) ||
        !parsePoint(statement.amountCommitment, pcm) ||
        !parsePoint(statement.balanceCommitment, pcb) ||
        !parsePoint(statement.senderPublicKey, pa) ||
        !parsePoint(statement.balanceCiphertext.R, b1) ||
        !parsePoint(statement.balanceCiphertext.S, b2))
        return false;

    secp256k1_pubkey t1Point;
    secp256k1_pubkey zrG;
    if (!detail::pointMulG(zr, zrG) ||
        !subtractMultiple(zrG, c1, e, t1Point))
        return false;

    std::vector<CompressedPoint> t2(statement.recipientPublicKeys.size());
    for (std::size_t i = 0; i < statement.recipientPublicKeys.size(); ++i)
    {
        secp256k1_pubkey recipient;
        secp256k1_pubkey encrypted;
        secp256k1_pubkey positive;
        secp256k1_pubkey reconstructed;
        if (!parsePoint(statement.recipientPublicKeys[i], recipient) ||
            !parsePoint(statement.encryptedAmounts[i], encrypted) ||
            !linearCombination(zm, recipient, zr, positive) ||
            !subtractMultiple(positive, encrypted, e, reconstructed) ||
            !serialize(reconstructed, t2[i]))
            return false;
    }

    secp256k1_pubkey tmPositive;
    secp256k1_pubkey tmPoint;
    secp256k1_pubkey tbPositive;
    secp256k1_pubkey tbPoint;
    secp256k1_pubkey tsk1Point;
    secp256k1_pubkey zskG;
    secp256k1_pubkey tsk2Positive;
    secp256k1_pubkey tsk2Point;
    if (!linearCombination(zm, h, zr, tmPositive) ||
        !subtractMultiple(tmPositive, pcm, e, tmPoint) ||
        !linearCombination(zb, h, zrho, tbPositive) ||
        !subtractMultiple(tbPositive, pcb, e, tbPoint) ||
        !detail::pointMulG(zsk, zskG) ||
        !subtractMultiple(zskG, pa, e, tsk1Point) ||
        !linearCombination(zb, b1, zsk, tsk2Positive) ||
        !subtractMultiple(tsk2Positive, b2, e, tsk2Point))
        return false;

    CompressedPoint t1;
    CompressedPoint tm;
    CompressedPoint tb;
    CompressedPoint tsk1;
    CompressedPoint tsk2;
    if (!serialize(t1Point, t1) || !serialize(tmPoint, tm) ||
        !serialize(tbPoint, tb) || !serialize(tsk1Point, tsk1) ||
        !serialize(tsk2Point, tsk2))
        return false;

    Scalar expected;
    if (!challengeSend(
            statement, t2, t1, tm, tb, tsk1, tsk2, transactionContextID, expected) ||
        !constantTimeEqual(e, expected))
        return false;
    if (challenge)
        *challenge = e;
    return true;
}

bool
createSendSigmaProof(
    SendSigmaStatement const& statement,
    SendSigmaWitness const& witness,
    SendSigmaProof& proof,
    Slice transactionContextID) noexcept
{
    if (statement.recipientPublicKeys.empty() ||
        statement.recipientPublicKeys.size() !=
            statement.encryptedAmounts.size() ||
        transactionContextID.size() != 32)
        return false;

    std::array<Scalar, 5> witnessScalars{
        witness.amount,
        witness.encryptionRandomness,
        witness.balance,
        witness.balanceBlinding,
        witness.senderSecret};
    for (auto const& scalar : witnessScalars)
    {
        Scalar parsed;
        if (!parseNonZeroScalar(makeSlice(scalar), parsed))
            return false;
    }

    CompressedPoint expected;
    if (!pedersenCommit(
            witness.amount, witness.encryptionRandomness, expected) ||
        expected != statement.amountCommitment ||
        !pedersenCommit(witness.balance, witness.balanceBlinding, expected) ||
        expected != statement.balanceCommitment)
        return false;

    secp256k1_pubkey h;
    secp256k1_pubkey c1;
    secp256k1_pubkey pa;
    secp256k1_pubkey b1;
    secp256k1_pubkey b2;
    secp256k1_pubkey expectedPoint;
    if (!parsePoint(pedersenGenerator(), h) ||
        !parsePoint(statement.sharedCiphertext, c1) ||
        !parsePoint(statement.senderPublicKey, pa) ||
        !parsePoint(statement.balanceCiphertext.R, b1) ||
        !parsePoint(statement.balanceCiphertext.S, b2) ||
        !detail::pointMulG(witness.encryptionRandomness, expectedPoint) ||
        !serialize(expectedPoint, expected) ||
        expected != statement.sharedCiphertext ||
        !detail::pointMulG(witness.senderSecret, expectedPoint) ||
        !serialize(expectedPoint, expected) ||
        expected != statement.senderPublicKey ||
        !linearCombination(
            witness.balance, b1, witness.senderSecret, expectedPoint) ||
        !serialize(expectedPoint, expected) ||
        expected != statement.balanceCiphertext.S)
        return false;

    for (std::size_t i = 0; i < statement.recipientPublicKeys.size(); ++i)
    {
        secp256k1_pubkey recipient;
        if (!parsePoint(statement.recipientPublicKeys[i], recipient) ||
            !linearCombination(
                witness.amount,
                recipient,
                witness.encryptionRandomness,
                expectedPoint) ||
            !serialize(expectedPoint, expected) ||
            expected != statement.encryptedAmounts[i])
            return false;
    }

    std::array<std::uint8_t, 5 * kScalarBytes> witnessBytes{};
    for (std::size_t i = 0; i < witnessScalars.size(); ++i)
        std::memcpy(
            witnessBytes.data() + i * kScalarBytes,
            witnessScalars[i].data(),
            kScalarBytes);
    std::array<Scalar, 5> alpha;
    static constexpr std::array<std::string_view, 5> labels{
        "send-m", "send-r", "send-b", "send-rho", "send-sk"};
    for (std::size_t i = 0; i < alpha.size(); ++i)
    {
        if (!deriveNonce(
                alpha[i],
                makeSlice(witnessBytes),
                transactionContextID,
                labels[i]))
            return false;
    }

    secp256k1_pubkey t1Point;
    secp256k1_pubkey tmPoint;
    secp256k1_pubkey tbPoint;
    secp256k1_pubkey tsk1Point;
    secp256k1_pubkey tsk2Point;
    if (!detail::pointMulG(alpha[1], t1Point) ||
        !linearCombination(alpha[0], h, alpha[1], tmPoint) ||
        !linearCombination(alpha[2], h, alpha[3], tbPoint) ||
        !detail::pointMulG(alpha[4], tsk1Point) ||
        !linearCombination(alpha[2], b1, alpha[4], tsk2Point))
        return false;

    std::vector<CompressedPoint> t2(statement.recipientPublicKeys.size());
    for (std::size_t i = 0; i < statement.recipientPublicKeys.size(); ++i)
    {
        secp256k1_pubkey recipient;
        secp256k1_pubkey commitment;
        if (!parsePoint(statement.recipientPublicKeys[i], recipient) ||
            !linearCombination(alpha[0], recipient, alpha[1], commitment) ||
            !serialize(commitment, t2[i]))
            return false;
    }

    CompressedPoint t1;
    CompressedPoint tm;
    CompressedPoint tb;
    CompressedPoint tsk1;
    CompressedPoint tsk2;
    if (!serialize(t1Point, t1) || !serialize(tmPoint, tm) ||
        !serialize(tbPoint, tb) || !serialize(tsk1Point, tsk1) ||
        !serialize(tsk2Point, tsk2))
        return false;

    Scalar e;
    if (!challengeSend(
            statement, t2, t1, tm, tb, tsk1, tsk2, transactionContextID, e))
        return false;

    std::array<Scalar, 6> output;
    output[0] = e;
    for (std::size_t i = 0; i < witnessScalars.size(); ++i)
    {
        Scalar product;
        if (!scalarMul(e, witnessScalars[i], product) ||
            !scalarAdd(alpha[i], product, output[i + 1]) ||
            scalarIsZero(output[i + 1]))
            return false;
    }
    writeScalars(output, proof);
    return true;
}

bool
verifyBalanceSigmaProof(
    BalanceSigmaStatement const& statement,
    BalanceSigmaProof const& proof,
    Slice transactionContextID) noexcept
{
    if (transactionContextID.size() != 32)
        return false;
    std::array<Scalar, 4> scalars;
    if (!parseScalars(proof, scalars))
        return false;
    auto const& [e, zb, zrho, zsk] = scalars;

    secp256k1_pubkey pa;
    secp256k1_pubkey b1;
    secp256k1_pubkey b2;
    secp256k1_pubkey pcb;
    secp256k1_pubkey h;
    if (!parsePoint(statement.senderPublicKey, pa) ||
        !parsePoint(statement.balanceCiphertext.R, b1) ||
        !parsePoint(statement.balanceCiphertext.S, b2) ||
        !parsePoint(statement.balanceCommitment, pcb) ||
        !parsePoint(pedersenGenerator(), h))
        return false;

    secp256k1_pubkey zskG;
    secp256k1_pubkey tsk1Point;
    secp256k1_pubkey tsk2Positive;
    secp256k1_pubkey tsk2Point;
    secp256k1_pubkey tbPositive;
    secp256k1_pubkey tbPoint;
    if (!detail::pointMulG(zsk, zskG) ||
        !subtractMultiple(zskG, pa, e, tsk1Point) ||
        !linearCombination(zb, b1, zsk, tsk2Positive) ||
        !subtractMultiple(tsk2Positive, b2, e, tsk2Point) ||
        !linearCombination(zb, h, zrho, tbPositive) ||
        !subtractMultiple(tbPositive, pcb, e, tbPoint))
        return false;

    CompressedPoint tsk1;
    CompressedPoint tsk2;
    CompressedPoint tb;
    if (!serialize(tsk1Point, tsk1) || !serialize(tsk2Point, tsk2) ||
        !serialize(tbPoint, tb))
        return false;

    Scalar expected;
    return challengeBalance(
               statement, tsk1, tsk2, tb, transactionContextID, expected) &&
        constantTimeEqual(e, expected);
}

bool
createBalanceSigmaProof(
    BalanceSigmaStatement const& statement,
    BalanceSigmaWitness const& witness,
    BalanceSigmaProof& proof,
    Slice transactionContextID) noexcept
{
    if (transactionContextID.size() != 32)
        return false;
    std::array<Scalar, 3> witnessScalars{
        witness.balance, witness.balanceBlinding, witness.senderSecret};
    for (auto const& scalar : witnessScalars)
    {
        Scalar parsed;
        if (!parseNonZeroScalar(makeSlice(scalar), parsed))
            return false;
    }

    CompressedPoint expected;
    secp256k1_pubkey b1;
    secp256k1_pubkey expectedPoint;
    if (!pedersenCommit(
            witness.balance, witness.balanceBlinding, expected) ||
        expected != statement.balanceCommitment ||
        !detail::pointMulG(witness.senderSecret, expectedPoint) ||
        !serialize(expectedPoint, expected) ||
        expected != statement.senderPublicKey ||
        !parsePoint(statement.balanceCiphertext.R, b1) ||
        !linearCombination(
            witness.balance, b1, witness.senderSecret, expectedPoint) ||
        !serialize(expectedPoint, expected) ||
        expected != statement.balanceCiphertext.S)
        return false;

    std::array<std::uint8_t, 3 * kScalarBytes> witnessBytes{};
    for (std::size_t i = 0; i < witnessScalars.size(); ++i)
        std::memcpy(
            witnessBytes.data() + i * kScalarBytes,
            witnessScalars[i].data(),
            kScalarBytes);
    std::array<Scalar, 3> alpha;
    static constexpr std::array<std::string_view, 3> labels{
        "balance-b", "balance-rho", "balance-sk"};
    for (std::size_t i = 0; i < alpha.size(); ++i)
    {
        if (!deriveNonce(
                alpha[i],
                makeSlice(witnessBytes),
                transactionContextID,
                labels[i]))
            return false;
    }

    secp256k1_pubkey h;
    secp256k1_pubkey tsk1Point;
    secp256k1_pubkey tsk2Point;
    secp256k1_pubkey tbPoint;
    if (!parsePoint(pedersenGenerator(), h) ||
        !detail::pointMulG(alpha[2], tsk1Point) ||
        !linearCombination(alpha[0], b1, alpha[2], tsk2Point) ||
        !linearCombination(alpha[0], h, alpha[1], tbPoint))
        return false;
    CompressedPoint tsk1;
    CompressedPoint tsk2;
    CompressedPoint tb;
    if (!serialize(tsk1Point, tsk1) || !serialize(tsk2Point, tsk2) ||
        !serialize(tbPoint, tb))
        return false;

    Scalar e;
    if (!challengeBalance(
            statement, tsk1, tsk2, tb, transactionContextID, e))
        return false;
    std::array<Scalar, 4> output;
    output[0] = e;
    for (std::size_t i = 0; i < witnessScalars.size(); ++i)
    {
        Scalar product;
        if (!scalarMul(e, witnessScalars[i], product) ||
            !scalarAdd(alpha[i], product, output[i + 1]) ||
            scalarIsZero(output[i + 1]))
            return false;
    }
    writeScalars(output, proof);
    return true;
}

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
