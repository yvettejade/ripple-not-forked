// Cross-proof consistency for confidential MPT ZKProof blobs.
//
// The per-primitive round trips live in confidential.cpp. These tests cover the
// seams between primitives: a ZKProof blob carries a compact sigma proof and a
// Bulletproof that must describe the SAME commitments, and the commitments must
// satisfy the homomorphic relations the transactors rely on. A blob assembled
// from two individually valid halves must not verify.
#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential.h>
#include <xrpl/protocol/TxFormats.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace xrpl;
using namespace xrpl::confidential;

namespace {

Scalar
mustRandomScalar()
{
    static std::uint32_t counter = 500001;
    for (std::uint32_t attempt = 0; attempt < 100000; ++attempt)
    {
        Scalar sk{};
        std::uint32_t const n = counter++;
        sk[24] = static_cast<std::uint8_t>((n >> 24) & 0xff);
        sk[25] = static_cast<std::uint8_t>((n >> 16) & 0xff);
        sk[26] = static_cast<std::uint8_t>((n >> 8) & 0xff);
        sk[27] = static_cast<std::uint8_t>(n & 0xff);
        sk[28] = 0x01;
        sk[31] = static_cast<std::uint8_t>(attempt & 0xff);
        CompressedPoint pk{};
        if (pointMulBase(sk, pk))
            return sk;
    }
    ADD_FAILURE() << "failed to find test scalar";
    return {};
}

struct Keypair
{
    Scalar sk{};
    CompressedPoint pk{};
};

Keypair
makeKey()
{
    Keypair kp;
    kp.sk = mustRandomScalar();
    EXPECT_TRUE(pointMulBase(kp.sk, kp.pk));
    return kp;
}

std::array<std::uint8_t, 20>
acct(std::uint8_t tag)
{
    std::array<std::uint8_t, 20> a{};
    a.fill(tag);
    return a;
}

std::array<std::uint8_t, 24>
issuance(std::uint8_t tag)
{
    std::array<std::uint8_t, 24> a{};
    a.fill(tag);
    return a;
}

// One complete, self-consistent Send: the ciphertexts, both commitments, the
// sigma proof and the range proof, all bound to one context id. Mirrors what
// ConfidentialMPTSend::doApply reconstructs and verifies.
struct SendBundle
{
    Keypair sender;
    Keypair recipient;
    Keypair issuer;
    std::uint64_t amount = 0;
    std::uint64_t balance = 0;
    Scalar r{};          // shared ElGamal randomness / PC_m blinding
    Scalar rho{};        // balance commitment blinding
    Scalar remBlind{};   // rho - r, blinding of the remainder commitment
    uint256 contextId{};
    SendSigmaPublicInput pub;
    SendSigmaProof sigma{};
    std::array<std::uint8_t, kAggregatedBulletproofBytes> range{};
    CompressedPoint remainder{};

    // The 946-byte on-ledger sfZKProof payload.
    std::vector<std::uint8_t>
    blob() const
    {
        std::vector<std::uint8_t> zk(kSendZkProofBytes);
        std::memcpy(zk.data(), sigma.data(), sigma.size());
        std::memcpy(zk.data() + sigma.size(), range.data(), range.size());
        return zk;
    }

    Slice
    ctx() const
    {
        return Slice(contextId.data(), contextId.size());
    }
};

SendBundle
makeSend(
    std::uint64_t amount,
    std::uint64_t balance,
    std::uint32_t sequence,
    std::uint32_t spendingVersion)
{
    SendBundle b;
    b.sender = makeKey();
    b.recipient = makeKey();
    b.issuer = makeKey();
    b.amount = amount;
    b.balance = balance;
    b.r = mustRandomScalar();
    b.rho = mustRandomScalar();

    Ciphertext balCt{};
    Scalar const rb = mustRandomScalar();
    EXPECT_TRUE(elgamalEncrypt(b.sender.pk, balance, rb, balCt));

    b.pub.recipientKeys = {b.sender.pk, b.recipient.pk, b.issuer.pk};
    b.pub.senderKey = b.sender.pk;
    b.pub.c2.clear();
    for (auto const& pk : b.pub.recipientKeys)
    {
        Ciphertext ct{};
        EXPECT_TRUE(elgamalEncrypt(pk, amount, b.r, ct));
        b.pub.c1 = ct.c1;  // shared across participants
        b.pub.c2.push_back(ct.c2);
    }
    EXPECT_TRUE(pedersenCommit(amount, b.r, b.pub.amountCommitment));
    EXPECT_TRUE(pedersenCommit(balance, b.rho, b.pub.balanceCommitment));
    b.pub.balanceC1 = balCt.c1;
    b.pub.balanceC2 = balCt.c2;

    auto const from = acct(0xA1);
    auto const to = acct(0xB2);
    auto const id = issuance(0xC3);
    b.contextId = transactionContextIDSend(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
        Slice(from.data(), from.size()),
        Slice(id.data(), id.size()),
        sequence,
        Slice(to.data(), to.size()),
        spendingVersion);

    SendSigmaWitness wit;
    wit.amount = amountToScalar(amount);
    wit.randomness = b.r;
    wit.balance = amountToScalar(balance);
    wit.balanceBlind = b.rho;
    wit.senderSk = b.sender.sk;
    EXPECT_TRUE(proveSendSigma(b.pub, wit, b.ctx(), b.sigma));

    EXPECT_TRUE(pointSub(
        b.pub.balanceCommitment, b.pub.amountCommitment, b.remainder));
    EXPECT_TRUE(subScalars(b.rho, b.r, b.remBlind));
    EXPECT_TRUE(proveBulletproofSend(
        b.pub.amountCommitment,
        b.remainder,
        amount,
        balance - amount,
        b.r,
        b.remBlind,
        b.range));
    return b;
}

// Verify a blob the way ConfidentialMPTSend::doApply does: sigma over the
// public inputs, range proof over PC_m and PC_b - PC_m.
bool
verifyBlob(
    SendSigmaPublicInput const& pub,
    Slice contextId,
    std::vector<std::uint8_t> const& zk)
{
    if (zk.size() != kSendZkProofBytes)
        return false;
    if (!verifySendSigma(
            pub, contextId, Slice(zk.data(), kSendSigmaProofBytes)))
        return false;
    CompressedPoint remaining{};
    if (!pointSub(pub.balanceCommitment, pub.amountCommitment, remaining))
        return false;
    return verifyBulletproofSend(
        pub.amountCommitment,
        remaining,
        Slice(zk.data() + kSendSigmaProofBytes, kAggregatedBulletproofBytes));
}

}  // namespace

TEST(ConfidentialProofCohesion, SendBlobVerifiesAgainstItsOwnInputs)
{
    auto const b = makeSend(10, 50, 7, 1);
    EXPECT_EQ(b.blob().size(), kSendZkProofBytes);
    EXPECT_TRUE(verifyBlob(b.pub, b.ctx(), b.blob()));
}

// The two halves of a blob are individually valid but describe different
// amounts. Splicing them must not produce an acceptable blob for either side.
TEST(ConfidentialProofCohesion, SendRejectsSplicedSigmaAndRangeProof)
{
    auto const a = makeSend(10, 50, 7, 1);
    auto const c = makeSend(25, 90, 8, 1);

    ASSERT_TRUE(verifyBlob(a.pub, a.ctx(), a.blob()));
    ASSERT_TRUE(verifyBlob(c.pub, c.ctx(), c.blob()));

    std::vector<std::uint8_t> aSigmaCRange(kSendZkProofBytes);
    std::memcpy(aSigmaCRange.data(), a.sigma.data(), a.sigma.size());
    std::memcpy(
        aSigmaCRange.data() + a.sigma.size(), c.range.data(), c.range.size());
    EXPECT_FALSE(verifyBlob(a.pub, a.ctx(), aSigmaCRange));

    std::vector<std::uint8_t> cSigmaARange(kSendZkProofBytes);
    std::memcpy(cSigmaARange.data(), c.sigma.data(), c.sigma.size());
    std::memcpy(
        cSigmaARange.data() + c.sigma.size(), a.range.data(), a.range.size());
    EXPECT_FALSE(verifyBlob(c.pub, c.ctx(), cSigmaARange));
}

// A whole valid blob replayed under another transaction's public inputs.
TEST(ConfidentialProofCohesion, SendBlobIsNotPortableAcrossTransactions)
{
    auto const a = makeSend(10, 50, 7, 1);
    auto const c = makeSend(25, 90, 8, 1);

    EXPECT_FALSE(verifyBlob(c.pub, c.ctx(), a.blob()));
    EXPECT_FALSE(verifyBlob(a.pub, a.ctx(), c.blob()));
    // Right inputs, wrong context (spending version advanced under the prover).
    EXPECT_FALSE(verifyBlob(a.pub, c.ctx(), a.blob()));
}

// Swapping in a different but well-formed commitment must break the blob, even
// when the substituted commitment opens to the same amount.
TEST(ConfidentialProofCohesion, SendRejectsSubstitutedCommitments)
{
    auto const b = makeSend(10, 50, 7, 1);

    {
        // PC_m for the same amount under an independent blinding.
        auto pub = b.pub;
        Scalar const other = mustRandomScalar();
        ASSERT_TRUE(pedersenCommit(b.amount, other, pub.amountCommitment));
        EXPECT_FALSE(verifyBlob(pub, b.ctx(), b.blob()));
    }
    {
        // PC_b for the same balance under an independent blinding.
        auto pub = b.pub;
        Scalar const other = mustRandomScalar();
        ASSERT_TRUE(pedersenCommit(b.balance, other, pub.balanceCommitment));
        EXPECT_FALSE(verifyBlob(pub, b.ctx(), b.blob()));
    }
    {
        // Commitments transposed.
        auto pub = b.pub;
        std::swap(pub.amountCommitment, pub.balanceCommitment);
        EXPECT_FALSE(verifyBlob(pub, b.ctx(), b.blob()));
    }
}

// The remainder the verifier derives by point subtraction must be exactly the
// commitment the prover range-proved: PC_b - PC_m == commit(b - m, rho - r).
// If this drifts, Send silently range-proves a value nobody committed to.
TEST(ConfidentialProofCohesion, SendRemainderMatchesHomomorphicCommitment)
{
    auto const b = makeSend(10, 50, 7, 1);

    CompressedPoint direct{};
    ASSERT_TRUE(pedersenCommit(b.balance - b.amount, b.remBlind, direct));
    EXPECT_EQ(direct, b.remainder);

    // Same value, unrelated blinding: not the remainder, and not provable
    // against the range proof the blob carries.
    Scalar const unrelated = mustRandomScalar();
    CompressedPoint decoy{};
    ASSERT_TRUE(pedersenCommit(b.balance - b.amount, unrelated, decoy));
    EXPECT_NE(decoy, b.remainder);
    EXPECT_FALSE(verifyBulletproofSend(
        b.pub.amountCommitment, decoy, Slice(b.range.data(), b.range.size())));
}

// Sigma binds PC_m to the ciphertext randomness r. A prover that blinds PC_m
// with an independent scalar breaks amount/commitment linkage.
TEST(ConfidentialProofCohesion, SendSigmaRequiresCommitmentReuseCiphertextRandomness)
{
    auto sender = makeKey();
    auto recipient = makeKey();
    auto issuer = makeKey();

    std::uint64_t const m = 10;
    std::uint64_t const bal = 50;
    Scalar const r = mustRandomScalar();
    Scalar const rho = mustRandomScalar();
    Scalar const rWrong = mustRandomScalar();

    Ciphertext balCt{};
    ASSERT_TRUE(elgamalEncrypt(sender.pk, bal, mustRandomScalar(), balCt));

    SendSigmaPublicInput pub;
    pub.recipientKeys = {sender.pk, recipient.pk, issuer.pk};
    pub.senderKey = sender.pk;
    for (auto const& pk : pub.recipientKeys)
    {
        Ciphertext ct{};
        ASSERT_TRUE(elgamalEncrypt(pk, m, r, ct));
        pub.c1 = ct.c1;
        pub.c2.push_back(ct.c2);
    }
    // PC_m committed with rWrong instead of the ciphertext randomness r.
    ASSERT_TRUE(pedersenCommit(m, rWrong, pub.amountCommitment));
    ASSERT_TRUE(pedersenCommit(bal, rho, pub.balanceCommitment));
    pub.balanceC1 = balCt.c1;
    pub.balanceC2 = balCt.c2;

    auto const from = acct(0xA1);
    auto const to = acct(0xB2);
    auto const id = issuance(0xC3);
    auto const context = transactionContextIDSend(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
        Slice(from.data(), from.size()),
        Slice(id.data(), id.size()),
        7,
        Slice(to.data(), to.size()),
        1);

    SendSigmaWitness wit;
    wit.amount = amountToScalar(m);
    wit.randomness = r;
    wit.balance = amountToScalar(bal);
    wit.balanceBlind = rho;
    wit.senderSk = sender.sk;

    SendSigmaProof proof{};
    Slice const ctx(context.data(), context.size());

    // The inconsistency must be caught either by the prover refusing the
    // witness or by the verifier rejecting the result. Branch so neither
    // outcome makes this test silently vacuous.
    if (proveSendSigma(pub, wit, ctx, proof))
    {
        EXPECT_FALSE(
            verifySendSigma(pub, ctx, Slice(proof.data(), proof.size())))
            << "PC_m blinded independently of the ciphertext randomness must "
               "not yield a verifying sigma proof";
    }
    else
    {
        SUCCEED() << "prover rejected the inconsistent PC_m witness";
    }
}

// ConvertBack pairs a sigma over PC_b with a range proof over PC_b - m*G. The
// range proof must be tied to the revealed amount actually being withdrawn.
TEST(ConfidentialProofCohesion, ConvertBackRangeProofBindsRevealedAmount)
{
    auto holder = makeKey();
    std::uint64_t const balance = 100;
    std::uint64_t const withdraw = 30;
    Scalar const rho = mustRandomScalar();

    Ciphertext balCt{};
    ASSERT_TRUE(
        elgamalEncrypt(holder.pk, balance, mustRandomScalar(), balCt));

    ConvertBackSigmaPublicInput pub;
    pub.holderKey = holder.pk;
    pub.balanceC1 = balCt.c1;
    pub.balanceC2 = balCt.c2;
    ASSERT_TRUE(pedersenCommit(balance, rho, pub.balanceCommitment));

    auto const who = acct(0xD4);
    auto const id = issuance(0xE5);
    auto const context = transactionContextIDConvertBack(
        static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
        Slice(who.data(), who.size()),
        Slice(id.data(), id.size()),
        11,
        1);
    Slice const ctx(context.data(), context.size());

    ConvertBackSigmaWitness wit;
    wit.balance = amountToScalar(balance);
    wit.balanceBlind = rho;
    wit.holderSk = holder.sk;
    ConvertBackSigmaProof sigma{};
    ASSERT_TRUE(proveConvertBackSigma(pub, wit, ctx, sigma));
    ASSERT_TRUE(
        verifyConvertBackSigma(pub, ctx, Slice(sigma.data(), sigma.size())));

    // Remainder for the honest withdrawal, derived exactly as
    // ConfidentialMPTConvertBack::doApply does: PC_b - m*G.
    CompressedPoint remainder{};
    CompressedPoint amountPoint{};
    ASSERT_TRUE(pointMulBase(amountToScalar(withdraw), amountPoint));
    ASSERT_TRUE(pointSub(pub.balanceCommitment, amountPoint, remainder));

    CompressedPoint expected{};
    ASSERT_TRUE(pedersenCommit(balance - withdraw, rho, expected));
    EXPECT_EQ(expected, remainder);

    std::array<std::uint8_t, kSingleBulletproofBytes> range{};
    ASSERT_TRUE(
        proveBulletproofSingle(remainder, balance - withdraw, rho, range));
    EXPECT_TRUE(
        verifyBulletproofSingle(remainder, Slice(range.data(), range.size())));

    // The same proof must not stand in for a larger withdrawal: the remainder
    // the verifier derives for m' != m is a different point.
    CompressedPoint biggerPoint{};
    CompressedPoint biggerRemainder{};
    ASSERT_TRUE(pointMulBase(amountToScalar(withdraw + 1), biggerPoint));
    ASSERT_TRUE(pointSub(pub.balanceCommitment, biggerPoint, biggerRemainder));
    EXPECT_NE(biggerRemainder, remainder);
    EXPECT_FALSE(verifyBulletproofSingle(
        biggerRemainder, Slice(range.data(), range.size())));
}
