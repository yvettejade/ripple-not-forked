#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol_autogen/transactions/ConfidentialMPTConvert.h>
#include <xrpl/protocol_autogen/transactions/ConfidentialMPTMergeInbox.h>

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
    TxTest env{allFeatures()};
    env.createAccount(alice, XRP(10'000));
    env.close();

    Blob const ct = filled(confidential_mpt::kCiphertextBytes);
    transactions::ConfidentialMPTConvertBuilder builder{
        alice, uint192(1), std::uint64_t{1}, makeSlice(ct), makeSlice(ct), nonzeroScalar()};
    Blob const key = filled(confidential_mpt::kPointBytes, 0x03);
    builder.setHolderEncryptionKey(makeSlice(key));
    // sfZKProof intentionally omitted.

    EXPECT_EQ(env.submit(builder, alice).ter, temMALFORMED);
}

TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, ConvertBadCiphertextLength)
{
    Account const alice("aliceCmptBadCt");
    TxTest env{allFeatures()};
    env.createAccount(alice, XRP(10'000));
    env.close();

    Blob const bad = filled(16);
    Blob const ok = filled(confidential_mpt::kCiphertextBytes);
    transactions::ConfidentialMPTConvertBuilder builder{
        alice,
        uint192(2),
        std::uint64_t{1},
        makeSlice(bad),
        makeSlice(ok),
        nonzeroScalar()};

    EXPECT_EQ(env.submit(builder, alice).ter, temBAD_CIPHERTEXT);
}

TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, MergeMissingObjects)
{
    Account const alice("aliceCmptMergeMissing");
    TxTest env{allFeatures()};
    ASSERT_TRUE(env.isEnabled(featureConfidentialTransfer));
    env.createAccount(alice, XRP(10'000));
    env.close();

    // TxTest::submit(builder) forces Fee=10; confidential txs require 10x base.
    transactions::ConfidentialMPTMergeInboxBuilder builder{alice, uint192(99)};
    builder.setSequence(env.getAccountRoot(alice.id()).getSequence());
    builder.setFee(XRPAmount(100));
    auto const stx = builder.build(alice.pk(), alice.sk()).getSTTx();
    EXPECT_EQ(env.submit(stx).ter, tecOBJECT_NOT_FOUND);
}

TEST(ConfidentialMPTConvertMergeInbox_Xls0096_Preflight_7f3a, ConvertMergeDisabledWithoutAmendment)
{
    Account const alice("aliceCmptDisabled");
    TxTest env{allFeatures() - featureConfidentialTransfer};
    ASSERT_FALSE(env.isEnabled(featureConfidentialTransfer));
    env.createAccount(alice, XRP(10'000));
    env.close();

    Blob const ct = filled(confidential_mpt::kCiphertextBytes);
    transactions::ConfidentialMPTConvertBuilder convert{
        alice, uint192(1), std::uint64_t{1}, makeSlice(ct), makeSlice(ct), nonzeroScalar()};
    Blob const key = filled(confidential_mpt::kPointBytes, 0x03);
    Blob const proof = filled(confidential_mpt::kKeyRegProofBytes);
    convert.setHolderEncryptionKey(makeSlice(key));
    convert.setZKProof(makeSlice(proof));
    EXPECT_EQ(env.submit(convert, alice).ter, temDISABLED);

    transactions::ConfidentialMPTMergeInboxBuilder merge{alice, uint192(1)};
    EXPECT_EQ(env.submit(merge, alice).ter, temDISABLED);
}

}  // namespace xrpl::test
