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
