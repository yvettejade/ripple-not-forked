#include <xrpl/crypto/ConfidentialMPT.h>

#include <utility/mpt_utility.h>

#include <gtest/gtest.h>

#include <array>

namespace xrpl::test {
namespace {

Slice
slice(Blob const& value)
{
    return {value.data(), value.size()};
}

}  // namespace

TEST(ConfidentialMPT, validatesAndCombinesCiphertexts)
{
    std::array<std::uint8_t, kMPT_PRIVKEY_SIZE> privateKey;
    Blob publicKey(kMPT_PUBKEY_SIZE);
    ASSERT_EQ(mpt_generate_keypair(privateKey.data(), publicKey.data()), 0);
    EXPECT_TRUE(confidential::isValidPublicKey(slice(publicKey)));

    Blob invalidPublicKey(confidential::publicKeySize - 1);
    EXPECT_FALSE(confidential::isValidPublicKey(slice(invalidPublicKey)));

    std::array<std::uint8_t, kMPT_BLINDING_FACTOR_SIZE> firstBlinding;
    std::array<std::uint8_t, kMPT_BLINDING_FACTOR_SIZE> secondBlinding;
    ASSERT_EQ(mpt_generate_blinding_factor(firstBlinding.data()), 0);
    ASSERT_EQ(mpt_generate_blinding_factor(secondBlinding.data()), 0);

    Blob first(confidential::ciphertextSize);
    Blob second(confidential::ciphertextSize);
    ASSERT_EQ(
        mpt_encrypt_amount(10, publicKey.data(), firstBlinding.data(), first.data()),
        0);
    ASSERT_EQ(
        mpt_encrypt_amount(20, publicKey.data(), secondBlinding.data(), second.data()),
        0);
    EXPECT_TRUE(confidential::isValidCiphertext(slice(first)));

    auto const sum = confidential::addCiphertexts(slice(first), slice(second));
    ASSERT_TRUE(sum);
    std::uint64_t amount = 0;
    EXPECT_EQ(
        mpt_decrypt_amount(sum->data(), privateKey.data(), &amount, 0, 30),
        0);
    EXPECT_EQ(amount, 30);

    auto const difference =
        confidential::subtractCiphertexts(slice(*sum), slice(first));
    ASSERT_TRUE(difference);
    EXPECT_EQ(
        mpt_decrypt_amount(
            difference->data(), privateKey.data(), &amount, 0, 30),
        0);
    EXPECT_EQ(amount, 20);
}

TEST(ConfidentialMPT, createsDeterministicEncryptedZero)
{
    std::array<std::uint8_t, kMPT_PRIVKEY_SIZE> privateKey;
    Blob publicKey(kMPT_PUBKEY_SIZE);
    ASSERT_EQ(mpt_generate_keypair(privateKey.data(), publicKey.data()), 0);

    AccountID const account;
    MPTID const issuanceID;
    auto const first = confidential::canonicalEncryptedZero(
        account, issuanceID, slice(publicKey));
    auto const second = confidential::canonicalEncryptedZero(
        account, issuanceID, slice(publicKey));
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_EQ(*first, *second);
    EXPECT_TRUE(confidential::isValidCiphertext(slice(*first)));

    std::uint64_t amount = 1;
    EXPECT_EQ(
        mpt_decrypt_amount(
            first->data(), privateKey.data(), &amount, 0, 1),
        0);
    EXPECT_EQ(amount, 0);
}

}  // namespace xrpl::test
