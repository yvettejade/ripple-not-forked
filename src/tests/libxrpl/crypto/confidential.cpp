#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/crypto/confidential/Proofs.h>
#include <xrpl/crypto/csprng.h>

#include <gtest/gtest.h>

#include <secp256k1.h>

#include <array>
#include <cstring>

using namespace xrpl;
using namespace xrpl::crypto::confidential;

namespace {

secp256k1_context const*
ctx()
{
    struct Holder
    {
        secp256k1_context* impl;
        Holder()
            : impl(secp256k1_context_create(
                  SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        {
        }
        ~Holder()
        {
            secp256k1_context_destroy(impl);
        }
    };
    static Holder const holder;
    return holder.impl;
}

bool
randomNonZeroScalar(Scalar& out)
{
    for (int i = 0; i < 32; ++i)
    {
        cryptoPrng()(out.data(), out.size());
        Scalar parsed;
        if (parseNonZeroScalar(Slice(out.data(), out.size()), parsed))
        {
            out = parsed;
            return true;
        }
    }
    return false;
}

bool
keyPair(Scalar& sk, CompressedPoint& pk)
{
    if (!randomNonZeroScalar(sk))
        return false;
    secp256k1_pubkey pub;
    if (secp256k1_ec_pubkey_create(ctx(), &pub, sk.data()) != 1)
        return false;
    std::size_t len = pk.size();
    return secp256k1_ec_pubkey_serialize(
               ctx(), pk.data(), &len, &pub, SECP256K1_EC_COMPRESSED) == 1 &&
        len == pk.size();
}

std::array<std::uint8_t, kAccountIDBytes>
fakeAccount(std::uint8_t fill)
{
    std::array<std::uint8_t, kAccountIDBytes> a{};
    a.fill(fill);
    return a;
}

std::array<std::uint8_t, kMPTIssuanceIDBytes>
fakeIssuance(std::uint8_t fill)
{
    std::array<std::uint8_t, kMPTIssuanceIDBytes> a{};
    a.fill(fill);
    return a;
}

}  // namespace

TEST(ConfidentialElGamal, CompressedPointStrictParsing)
{
    Scalar sk;
    CompressedPoint pk;
    ASSERT_TRUE(keyPair(sk, pk));

    CompressedPoint out;
    EXPECT_TRUE(parseCompressedPoint(Slice(pk.data(), pk.size()), out));
    EXPECT_EQ(out, pk);

    // Wrong length
    EXPECT_FALSE(parseCompressedPoint(Slice(pk.data(), 32), out));

    // Uncompressed prefix rejected
    CompressedPoint bad = pk;
    bad[0] = 0x04;
    EXPECT_FALSE(parseCompressedPoint(Slice(bad.data(), bad.size()), out));

    // Off-curve / garbage
    bad = pk;
    bad[0] = 0x02;
    bad.fill(0x11);
    bad[0] = 0x02;
    EXPECT_FALSE(parseCompressedPoint(Slice(bad.data(), bad.size()), out));
}

TEST(ConfidentialElGamal, ScalarParsingAndArithmetic)
{
    Scalar a{};
    a[31] = 7;
    Scalar b{};
    b[31] = 11;
    Scalar out;

    ASSERT_TRUE(parseScalar(Slice(a.data(), a.size()), out));
    EXPECT_EQ(out, a);
    EXPECT_FALSE(scalarIsZero(a));
    EXPECT_TRUE(scalarIsZero(Scalar{}));

    // Order itself is not canonical
    Scalar order = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
        0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    EXPECT_FALSE(parseScalar(Slice(order.data(), order.size()), out));

    ASSERT_TRUE(scalarAdd(a, b, out));
    EXPECT_EQ(out[31], 18);
    ASSERT_TRUE(scalarSub(out, b, out));
    EXPECT_EQ(out, a);
    ASSERT_TRUE(scalarMul(a, b, out));
    EXPECT_EQ(out[31], 77);
    ASSERT_TRUE(scalarNegate(a, out));
    Scalar sum;
    ASSERT_TRUE(scalarAdd(a, out, sum));
    EXPECT_TRUE(scalarIsZero(sum));

    Scalar fromU64;
    ASSERT_TRUE(scalarFromUint64(0x0102030405060708ULL, fromU64));
    EXPECT_EQ(fromU64[24], 0x01);
    EXPECT_EQ(fromU64[31], 0x08);
    EXPECT_FALSE(parseNonZeroScalar(Slice(Scalar{}.data(), 32), out));
}

TEST(ConfidentialElGamal, CiphertextParseAndHomomorphism)
{
    Scalar sk;
    CompressedPoint pk;
    ASSERT_TRUE(keyPair(sk, pk));

    Scalar r1;
    Scalar r2;
    ASSERT_TRUE(randomNonZeroScalar(r1));
    ASSERT_TRUE(randomNonZeroScalar(r2));

    Ciphertext c1;
    Ciphertext c2;
    ASSERT_TRUE(encrypt(pk, 5, r1, c1));
    ASSERT_TRUE(encrypt(pk, 9, r2, c2));

    CiphertextBlob blob;
    ASSERT_TRUE(serializeCiphertext(c1, blob));
    Ciphertext parsed;
    ASSERT_TRUE(parseCiphertext(Slice(blob.data(), blob.size()), parsed));
    EXPECT_EQ(parsed.R, c1.R);
    EXPECT_EQ(parsed.S, c1.S);
    EXPECT_FALSE(parseCiphertext(Slice(blob.data(), 65), parsed));

    Ciphertext sum;
    ASSERT_TRUE(ciphertextAdd(c1, c2, sum));
    Ciphertext expected;
    Scalar rSum;
    ASSERT_TRUE(scalarAdd(r1, r2, rSum));
    ASSERT_TRUE(encrypt(pk, 14, rSum, expected));
    EXPECT_EQ(sum.R, expected.R);
    EXPECT_EQ(sum.S, expected.S);

    Ciphertext diff;
    ASSERT_TRUE(ciphertextSub(sum, c2, diff));
    EXPECT_EQ(diff.R, c1.R);
    EXPECT_EQ(diff.S, c1.S);
}

TEST(ConfidentialElGamal, DeterministicEncryptionVerification)
{
    Scalar sk;
    CompressedPoint pk;
    ASSERT_TRUE(keyPair(sk, pk));
    Scalar r;
    ASSERT_TRUE(randomNonZeroScalar(r));

    Ciphertext ct;
    ASSERT_TRUE(encrypt(pk, 42, r, ct));
    EXPECT_TRUE(verifyDeterministicEncryption(ct, pk, 42, r));
    EXPECT_FALSE(verifyDeterministicEncryption(ct, pk, 41, r));

    Scalar r2;
    ASSERT_TRUE(randomNonZeroScalar(r2));
    EXPECT_FALSE(verifyDeterministicEncryption(ct, pk, 42, r2));

    // Zero plaintext
    Ciphertext z;
    ASSERT_TRUE(encrypt(pk, 0, r, z));
    EXPECT_TRUE(verifyDeterministicEncryption(z, pk, 0, r));
}

TEST(ConfidentialElGamal, CanonicalEncryptedZero)
{
    Scalar sk;
    CompressedPoint pk;
    ASSERT_TRUE(keyPair(sk, pk));
    auto acct = fakeAccount(0xAB);
    auto iss = fakeIssuance(0xCD);

    Ciphertext z;
    ASSERT_TRUE(canonicalEncryptedZero(
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        pk,
        z));
    EXPECT_TRUE(isCanonicalEncryptedZero(
        z,
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        pk));

    // Deterministic
    Ciphertext z2;
    ASSERT_TRUE(canonicalEncryptedZero(
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        pk,
        z2));
    EXPECT_EQ(z.R, z2.R);
    EXPECT_EQ(z.S, z2.S);

    // Different account => different ciphertext
    auto acct2 = fakeAccount(0xEF);
    Ciphertext z3;
    ASSERT_TRUE(canonicalEncryptedZero(
        Slice(acct2.data(), acct2.size()),
        Slice(iss.data(), iss.size()),
        pk,
        z3));
    EXPECT_NE(z.R, z3.R);

    // Wrong length inputs rejected
    EXPECT_FALSE(canonicalEncryptedZero(
        Slice(acct.data(), 19), Slice(iss.data(), iss.size()), pk, z));
}

TEST(ConfidentialProofs, SchnorrPoKPositiveAndNegative)
{
    Scalar sk;
    CompressedPoint pk;
    ASSERT_TRUE(keyPair(sk, pk));

    SchnorrProof proof;
    ASSERT_TRUE(createSchnorrProofOfKnowledge(sk, pk, proof));
    EXPECT_TRUE(verifySchnorrProofOfKnowledge(pk, proof));

    // Bind optional extra context
    char const extra[] = "holder-register";
    SchnorrProof proof2;
    ASSERT_TRUE(createSchnorrProofOfKnowledge(
        sk, pk, proof2, Slice(extra, sizeof(extra) - 1)));
    EXPECT_TRUE(verifySchnorrProofOfKnowledge(
        pk, proof2, Slice(extra, sizeof(extra) - 1)));
    EXPECT_FALSE(verifySchnorrProofOfKnowledge(pk, proof2));
    EXPECT_FALSE(verifySchnorrProofOfKnowledge(
        pk, proof, Slice(extra, sizeof(extra) - 1)));

    // Tamper challenge
    SchnorrProof bad = proof;
    bad[0] ^= 0x01;
    EXPECT_FALSE(verifySchnorrProofOfKnowledge(pk, bad));

    // Tamper response
    bad = proof;
    bad[63] ^= 0x01;
    EXPECT_FALSE(verifySchnorrProofOfKnowledge(pk, bad));

    // Wrong public key
    Scalar sk2;
    CompressedPoint pk2;
    ASSERT_TRUE(keyPair(sk2, pk2));
    EXPECT_FALSE(verifySchnorrProofOfKnowledge(pk2, proof));
}

TEST(ConfidentialProofs, ClawbackPositiveAndNegative)
{
    Scalar issuerSk;
    CompressedPoint issuerPk;
    ASSERT_TRUE(keyPair(issuerSk, issuerPk));

    Scalar r;
    ASSERT_TRUE(randomNonZeroScalar(r));
    std::uint64_t const m = 123456789ULL;
    Ciphertext ct;
    ASSERT_TRUE(encrypt(issuerPk, m, r, ct));

    SchnorrProof proof;
    ASSERT_TRUE(createClawbackProof(issuerSk, issuerPk, ct, m, proof));
    EXPECT_TRUE(verifyClawbackProof(issuerPk, ct, m, proof));

    // Wrong amount
    EXPECT_FALSE(verifyClawbackProof(issuerPk, ct, m + 1, proof));

    // Tampered proof
    SchnorrProof bad = proof;
    bad[31] ^= 0xff;
    EXPECT_FALSE(verifyClawbackProof(issuerPk, ct, m, bad));

    // Wrong ciphertext
    Scalar r2;
    ASSERT_TRUE(randomNonZeroScalar(r2));
    Ciphertext ct2;
    ASSERT_TRUE(encrypt(issuerPk, m, r2, ct2));
    EXPECT_FALSE(verifyClawbackProof(issuerPk, ct2, m, proof));

    // Zero-amount clawbacks are not valid XLS-0096 transactions.
    Ciphertext z;
    ASSERT_TRUE(encrypt(issuerPk, 0, r, z));
    SchnorrProof zProof;
    EXPECT_FALSE(createClawbackProof(issuerSk, issuerPk, z, 0, zProof));
    EXPECT_FALSE(verifyClawbackProof(issuerPk, z, 0, zProof));
}

TEST(ConfidentialProofs, SendCompactSigma)
{
    Scalar senderSk;
    Scalar destinationSk;
    Scalar issuerSk;
    CompressedPoint senderPk;
    CompressedPoint destinationPk;
    CompressedPoint issuerPk;
    ASSERT_TRUE(keyPair(senderSk, senderPk));
    ASSERT_TRUE(keyPair(destinationSk, destinationPk));
    ASSERT_TRUE(keyPair(issuerSk, issuerPk));

    Scalar amount;
    Scalar balance;
    Scalar encryptionRandomness;
    Scalar balanceRandomness;
    Scalar balanceBlinding;
    ASSERT_TRUE(scalarFromUint64(17, amount));
    ASSERT_TRUE(scalarFromUint64(91, balance));
    ASSERT_TRUE(randomNonZeroScalar(encryptionRandomness));
    ASSERT_TRUE(randomNonZeroScalar(balanceRandomness));
    ASSERT_TRUE(randomNonZeroScalar(balanceBlinding));

    Ciphertext senderAmount;
    Ciphertext destinationAmount;
    Ciphertext issuerAmount;
    Ciphertext balanceCiphertext;
    ASSERT_TRUE(encrypt(senderPk, 17, encryptionRandomness, senderAmount));
    ASSERT_TRUE(encrypt(
        destinationPk, 17, encryptionRandomness, destinationAmount));
    ASSERT_TRUE(encrypt(issuerPk, 17, encryptionRandomness, issuerAmount));
    ASSERT_TRUE(encrypt(senderPk, 91, balanceRandomness, balanceCiphertext));

    CompressedPoint amountCommitment;
    CompressedPoint balanceCommitment;
    ASSERT_TRUE(pedersenCommit(
        amount, encryptionRandomness, amountCommitment));
    ASSERT_TRUE(
        pedersenCommit(balance, balanceBlinding, balanceCommitment));

    SendSigmaStatement statement{
        .recipientPublicKeys = {senderPk, destinationPk, issuerPk},
        .senderPublicKey = senderPk,
        .sharedCiphertext = senderAmount.R,
        .encryptedAmounts = {
            senderAmount.S, destinationAmount.S, issuerAmount.S},
        .amountCommitment = amountCommitment,
        .balanceCommitment = balanceCommitment,
        .balanceCiphertext = balanceCiphertext};
    SendSigmaWitness witness{
        .amount = amount,
        .encryptionRandomness = encryptionRandomness,
        .balance = balance,
        .balanceBlinding = balanceBlinding,
        .senderSecret = senderSk};
    std::array<std::uint8_t, 32> context{};
    context.fill(0x42);

    SendSigmaProof proof;
    ASSERT_TRUE(createSendSigmaProof(
        statement, witness, proof, makeSlice(context)));
    Scalar challenge;
    EXPECT_TRUE(verifySendSigmaProof(
        statement, proof, makeSlice(context), &challenge));
    EXPECT_FALSE(scalarIsZero(challenge));

    auto badProof = proof;
    badProof.back() ^= 1;
    EXPECT_FALSE(
        verifySendSigmaProof(statement, badProof, makeSlice(context)));

    auto badContext = context;
    badContext.front() ^= 1;
    EXPECT_FALSE(
        verifySendSigmaProof(statement, proof, makeSlice(badContext)));

    auto badStatement = statement;
    badStatement.encryptedAmounts[1] = senderAmount.S;
    EXPECT_FALSE(
        verifySendSigmaProof(badStatement, proof, makeSlice(context)));
}

TEST(ConfidentialProofs, ConvertBackCompactSigma)
{
    Scalar holderSk;
    CompressedPoint holderPk;
    ASSERT_TRUE(keyPair(holderSk, holderPk));

    Scalar balance;
    Scalar balanceRandomness;
    Scalar balanceBlinding;
    ASSERT_TRUE(scalarFromUint64(200, balance));
    ASSERT_TRUE(randomNonZeroScalar(balanceRandomness));
    ASSERT_TRUE(randomNonZeroScalar(balanceBlinding));

    Ciphertext balanceCiphertext;
    CompressedPoint balanceCommitment;
    ASSERT_TRUE(
        encrypt(holderPk, 200, balanceRandomness, balanceCiphertext));
    ASSERT_TRUE(
        pedersenCommit(balance, balanceBlinding, balanceCommitment));

    BalanceSigmaStatement statement{
        .senderPublicKey = holderPk,
        .balanceCiphertext = balanceCiphertext,
        .balanceCommitment = balanceCommitment};
    BalanceSigmaWitness witness{
        .balance = balance,
        .balanceBlinding = balanceBlinding,
        .senderSecret = holderSk};
    std::array<std::uint8_t, 32> context{};
    context.fill(0x24);

    BalanceSigmaProof proof;
    ASSERT_TRUE(createBalanceSigmaProof(
        statement, witness, proof, makeSlice(context)));
    EXPECT_TRUE(
        verifyBalanceSigmaProof(statement, proof, makeSlice(context)));

    auto bad = proof;
    bad[31] ^= 1;
    EXPECT_FALSE(
        verifyBalanceSigmaProof(statement, bad, makeSlice(context)));

    Scalar otherBlind;
    ASSERT_TRUE(randomNonZeroScalar(otherBlind));
    ASSERT_TRUE(
        pedersenCommit(balance, otherBlind, statement.balanceCommitment));
    EXPECT_FALSE(
        verifyBalanceSigmaProof(statement, proof, makeSlice(context)));
}
