#include <xrpl/protocol_autogen/transactions/ConfidentialMPTConvert.h>
#include <xrpl/protocol_autogen/transactions/ConfidentialMPTMergeInbox.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>

#include <gtest/gtest.h>
#include <helpers/Account.h>
#include <helpers/TxTest.h>

#include <cstdint>

namespace xrpl::test {
namespace {

Blob
filled(std::size_t n, unsigned char fill = 0x02)
{
    return Blob(n, fill);
}

uint256
nonzeroScalar()
{
    uint256 value(0);
    *(value.end() - 1) = 1;
    return value;
}

}  // namespace

// Unique focused preflight coverage for XLS-0096 Convert + MergeInbox.
TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, ConvertKeyWithoutProofMalformed)
{
    Account const alice("aliceCmptKeyNoProof");
    TxTest env;
    env.createAccount(alice, XRP(10'000));
    env.close();

    Blob const ct = filled(confidential_mpt::kCiphertextBytes);
    transactions::ConfidentialMPTConvertBuilder builder{
        alice,
        uint192(1),
        std::uint64_t{1},
        ct,
        ct,
        nonzeroScalar()};
    builder.setHolderEncryptionKey(filled(confidential_mpt::kPointBytes, 0x03));
    // sfZKProof intentionally omitted.

    EXPECT_EQ(env.submit(builder, alice).ter, temMALFORMED);
}

TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, ConvertBadCiphertextLength)
{
    Account const alice("aliceCmptBadCt");
    TxTest env;
    env.createAccount(alice, XRP(10'000));
    env.close();

    transactions::ConfidentialMPTConvertBuilder builder{
        alice,
        uint192(2),
        std::uint64_t{1},
        filled(16),
        filled(confidential_mpt::kCiphertextBytes),
        nonzeroScalar()};

    EXPECT_EQ(env.submit(builder, alice).ter, temBAD_CIPHERTEXT);
}

TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, MergeMissingObjects)
{
    Account const alice("aliceCmptMergeMissing");
    TxTest env;
    env.createAccount(alice, XRP(10'000));
    env.close();

    transactions::ConfidentialMPTMergeInboxBuilder builder{alice, uint192(99)};
    auto const ter = env.submit(builder, alice).ter;
    // Missing issuance/token, or amendment absent from the feature set.
    EXPECT_TRUE(ter == tecOBJECT_NOT_FOUND || ter == temDISABLED);
}

}  // namespace xrpl::test
