#include <xrpl/protocol/Confidential.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/KeyType.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Seed.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <utility>

using namespace xrpl;

namespace {

std::pair<PublicKey, SecretKey>
secpKeys(char const* phrase)
{
    return generateKeyPair(KeyType::Secp256k1, generateSeed(phrase));
}

uint256
scalarFromSecret(SecretKey const& sk)
{
    uint256 r;
    std::memcpy(r.data(), sk.data(), 32);
    return r;
}

Slice
skSlice(SecretKey const& sk)
{
    return Slice(sk.data(), sk.size());
}

}  // namespace

TEST(Confidential, PubKeyValidation)
{
    auto const [pk, sk] = secpKeys("holder");
    EXPECT_TRUE(isConfidentialPubKey(pk.slice()));
    EXPECT_TRUE(isConfidentialScalar(scalarFromSecret(sk)));

    auto const edPk = generateKeyPair(KeyType::Ed25519, generateSeed("ed")).first;
    EXPECT_FALSE(isConfidentialPubKey(edPk.slice()));

    std::array<unsigned char, kConfidentialPubKeyLength> zeros{};
    zeros[0] = 0x02;
    EXPECT_FALSE(isConfidentialPubKey(Slice(zeros.data(), zeros.size())));

    EXPECT_FALSE(isConfidentialScalar(uint256{}));
}

TEST(Confidential, EncryptAndMatch)
{
    auto const pk = secpKeys("enc").first;
    auto const r = scalarFromSecret(secpKeys("blind").second);

    auto const ct = elgamalEncrypt(pk.slice(), 42, r);
    ASSERT_TRUE(ct);
    EXPECT_EQ(ct->size(), kConfidentialCiphertextLength);
    EXPECT_TRUE(isConfidentialCiphertext(*ct));
    EXPECT_TRUE(elgamalMatches(*ct, pk.slice(), 42, r));
    EXPECT_FALSE(elgamalMatches(*ct, pk.slice(), 41, r));

    auto const zero = elgamalEncrypt(pk.slice(), 0, r);
    ASSERT_TRUE(zero);
    EXPECT_TRUE(elgamalMatches(*zero, pk.slice(), 0, r));
}

TEST(Confidential, HomomorphicAddSub)
{
    auto const pk = secpKeys("homo").first;
    auto const r1 = scalarFromSecret(secpKeys("r1").second);
    auto const r2 = scalarFromSecret(secpKeys("r2").second);

    auto const c1 = elgamalEncrypt(pk.slice(), 3, r1);
    auto const c2 = elgamalEncrypt(pk.slice(), 4, r2);
    ASSERT_TRUE(c1);
    ASSERT_TRUE(c2);

    auto const sum = elgamalAdd(*c1, *c2);
    ASSERT_TRUE(sum);
    auto const back = elgamalSub(*sum, *c2);
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, *c1);

    auto const zeroed = elgamalSub(*c1, *c1);
    ASSERT_TRUE(zeroed);
    EXPECT_TRUE(isConfidentialCiphertext(*zeroed));
}

TEST(Confidential, EncZeroDeterministic)
{
    auto const pk = secpKeys("zero-pk").first;
    auto const account = calcAccountID(secpKeys("acct").first);
    auto const issuer = calcAccountID(secpKeys("iss").first);
    auto const mptId = makeMptID(1, issuer);

    auto const a = encZero(account, issuer, mptId, pk.slice());
    auto const b = encZero(account, issuer, mptId, pk.slice());
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(*a, *b);
    EXPECT_TRUE(isConfidentialCiphertext(*a));

    auto const other = encZero(calcAccountID(secpKeys("acct2").first), issuer, mptId, pk.slice());
    ASSERT_TRUE(other);
    EXPECT_NE(*a, *other);
}

TEST(Confidential, SchnorrProveVerify)
{
    auto const [pk, sk] = secpKeys("schnorr");
    auto const account = calcAccountID(secpKeys("acct").first);
    auto const mptId = makeMptID(7, account);
    auto const transcript = convertSchnorrTranscript(account, mptId);

    auto const proof = schnorrProve(pk.slice(), skSlice(sk), transcript);
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->size(), kConfidentialSchnorrProofLength);
    EXPECT_TRUE(schnorrVerify(pk.slice(), *proof, transcript));

    auto const other = convertSchnorrTranscript(calcAccountID(secpKeys("other").first), mptId);
    EXPECT_FALSE(schnorrVerify(pk.slice(), *proof, other));

    std::array<unsigned char, kConfidentialSchnorrProofLength> garbage{};
    garbage[0] = 0x01;
    EXPECT_FALSE(schnorrVerify(pk.slice(), Slice(garbage.data(), garbage.size()), transcript));
}

TEST(Confidential, RejectsBadCiphertext)
{
    std::array<unsigned char, kConfidentialCiphertextLength> zeros{};
    EXPECT_FALSE(isConfidentialCiphertext(Slice(zeros.data(), zeros.size())));
    EXPECT_FALSE(elgamalAdd(Slice(zeros.data(), zeros.size()), Slice(zeros.data(), zeros.size())));
}


TEST(Confidential, PedersenCommit)
{
    auto const r = scalarFromSecret(secpKeys("pedersen-blind").second);
    auto const C = pedersenCommit(42, r);
    ASSERT_TRUE(C);
    EXPECT_EQ(C->size(), kConfidentialCommitmentLength);
    EXPECT_TRUE(isConfidentialPubKey(*C));
    auto const C0 = pedersenCommit(0, r);
    ASSERT_TRUE(C0);
    EXPECT_NE(*C, *C0);
}

TEST(Confidential, ClawbackProveVerify)
{
    auto const [pk, sk] = secpKeys("claw-iss");
    auto const r = scalarFromSecret(secpKeys("claw-r").second);
    std::uint64_t const m = 99;
    auto const ct = elgamalEncrypt(pk.slice(), m, r);
    ASSERT_TRUE(ct);
    auto const issuer = calcAccountID(pk);
    auto const holder = calcAccountID(secpKeys("claw-hold").first);
    auto const mptId = makeMptID(3, issuer);
    auto const transcript = clawbackTranscript(issuer, holder, mptId);

    auto const proof = clawbackProve(*ct, pk.slice(), m, skSlice(sk), transcript);
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->size(), kConfidentialClawbackProofLength);
    EXPECT_TRUE(clawbackVerify(*ct, pk.slice(), m, *proof, transcript));
    EXPECT_FALSE(clawbackVerify(*ct, pk.slice(), m - 1, *proof, transcript));
}

TEST(Confidential, ConvertBackProveVerify)
{
    auto const [holderPk, holderSk] = secpKeys("cb-holder");
    auto const issuerPk = secpKeys("cb-issuer").first;
    auto const auditorPk = secpKeys("cb-auditor").first;
    auto const r = scalarFromSecret(secpKeys("cb-r").second);
    auto const gamma = scalarFromSecret(secpKeys("cb-gamma").second);
    auto const spendR = scalarFromSecret(secpKeys("cb-spend-r").second);
    std::uint64_t const balance = 100;
    std::uint64_t const amount = 25;
    auto const spending = elgamalEncrypt(holderPk.slice(), balance, spendR);
    ASSERT_TRUE(spending);

    auto const account = calcAccountID(holderPk);
    auto const mptId = makeMptID(9, calcAccountID(issuerPk));
    auto const transcript = convertBackTranscript(account, mptId, 1);

    auto const proof = convertBackProve(
        holderPk.slice(),
        skSlice(holderSk),
        issuerPk.slice(),
        std::nullopt,
        *spending,
        amount,
        balance,
        r,
        gamma,
        transcript);
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->zkProof.size(), kConfidentialConvertBackZkLength);
    EXPECT_TRUE(convertBackVerify(
        holderPk.slice(),
        issuerPk.slice(),
        std::nullopt,
        *spending,
        amount,
        proof->holderEnc,
        proof->issuerEnc,
        std::nullopt,
        r,
        proof->balanceCommitment,
        proof->zkProof,
        transcript));

    auto const withAud = convertBackProve(
        holderPk.slice(),
        skSlice(holderSk),
        issuerPk.slice(),
        std::optional<Slice>{auditorPk.slice()},
        *spending,
        amount,
        balance,
        r,
        gamma,
        transcript);
    ASSERT_TRUE(withAud);
    EXPECT_FALSE(withAud->auditorEnc.empty());
    EXPECT_TRUE(convertBackVerify(
        holderPk.slice(),
        issuerPk.slice(),
        std::optional<Slice>{auditorPk.slice()},
        *spending,
        amount,
        withAud->holderEnc,
        withAud->issuerEnc,
        std::optional<Slice>{withAud->auditorEnc},
        r,
        withAud->balanceCommitment,
        withAud->zkProof,
        transcript));

    // Tampered zkProof fails
    auto tampered = withAud->zkProof;
    tampered.data()[0] ^= 0x01;
    EXPECT_FALSE(convertBackVerify(
        holderPk.slice(),
        issuerPk.slice(),
        std::optional<Slice>{auditorPk.slice()},
        *spending,
        amount,
        withAud->holderEnc,
        withAud->issuerEnc,
        std::optional<Slice>{withAud->auditorEnc},
        r,
        withAud->balanceCommitment,
        tampered,
        transcript));
}

TEST(Confidential, SendProveVerify)
{
    auto const [senderPk, senderSk] = secpKeys("send-sender");
    auto const destPk = secpKeys("send-dest").first;
    auto const issuerPk = secpKeys("send-iss").first;
    auto const auditorPk = secpKeys("send-aud").first;
    auto const r = scalarFromSecret(secpKeys("send-r").second);
    auto const gamma = scalarFromSecret(secpKeys("send-gamma").second);
    auto const spendR = scalarFromSecret(secpKeys("send-spend-r").second);
    std::uint64_t const balance = 80;
    std::uint64_t const amount = 17;
    auto const spending = elgamalEncrypt(senderPk.slice(), balance, spendR);
    ASSERT_TRUE(spending);

    auto const transcript = sendTranscript(
        calcAccountID(senderPk), calcAccountID(destPk), makeMptID(2, calcAccountID(issuerPk)), 4);

    auto const proof = sendProve(
        senderPk.slice(),
        skSlice(senderSk),
        destPk.slice(),
        issuerPk.slice(),
        std::nullopt,
        *spending,
        amount,
        balance,
        r,
        gamma,
        transcript);
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->zkProof.size(), kConfidentialSendZkLength);
    EXPECT_TRUE(sendVerify(
        senderPk.slice(),
        destPk.slice(),
        issuerPk.slice(),
        std::nullopt,
        *spending,
        proof->senderEnc,
        proof->destEnc,
        proof->issuerEnc,
        std::nullopt,
        proof->amountCommitment,
        proof->balanceCommitment,
        proof->zkProof,
        transcript));

    auto tampered = proof->zkProof;
    tampered.data()[40] ^= 0xff;
    EXPECT_FALSE(sendVerify(
        senderPk.slice(),
        destPk.slice(),
        issuerPk.slice(),
        std::nullopt,
        *spending,
        proof->senderEnc,
        proof->destEnc,
        proof->issuerEnc,
        std::nullopt,
        proof->amountCommitment,
        proof->balanceCommitment,
        tampered,
        transcript));

    auto const withAud = sendProve(
        senderPk.slice(),
        skSlice(senderSk),
        destPk.slice(),
        issuerPk.slice(),
        std::optional<Slice>{auditorPk.slice()},
        *spending,
        amount,
        balance,
        r,
        gamma,
        transcript);
    ASSERT_TRUE(withAud);
    EXPECT_FALSE(withAud->auditorEnc.empty());
    EXPECT_TRUE(sendVerify(
        senderPk.slice(),
        destPk.slice(),
        issuerPk.slice(),
        std::optional<Slice>{auditorPk.slice()},
        *spending,
        withAud->senderEnc,
        withAud->destEnc,
        withAud->issuerEnc,
        std::optional<Slice>{withAud->auditorEnc},
        withAud->amountCommitment,
        withAud->balanceCommitment,
        withAud->zkProof,
        transcript));
}
