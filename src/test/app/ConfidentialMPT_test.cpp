#include <test/jtx/Env.h>
#include <test/jtx/mpt.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TxFlags.h>

#include <utility/mpt_utility.h>

#include <array>
#include <string>

namespace xrpl::test {

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    static std::string
    publicKey()
    {
        std::array<std::uint8_t, kMPT_PRIVKEY_SIZE> privateKey;
        std::array<std::uint8_t, kMPT_PUBKEY_SIZE> publicKey;
        if (mpt_generate_keypair(privateKey.data(), publicKey.data()) != 0)
            Throw<std::runtime_error>("Unable to generate confidential MPT key");
        return {
            reinterpret_cast<char const*>(publicKey.data()),
            publicKey.size()};
    }

    FeatureBitset
    features() const
    {
        return testableAmendments() | featureDynamicMPT |
            featureConfidentialTransfer;
    }

    void
    testCreate()
    {
        testcase("confidential issuance creation");
        using namespace jtx;
        Account const issuer{"issuer"};

        {
            Env env{*this, features() - featureConfidentialTransfer};
            MPTTester mpt{env, issuer};
            mpt.create(
                {.flags = tfMPTCanHoldConfidentialBalance,
                 .err = temDISABLED});
        }
        {
            Env env{*this, features()};
            MPTTester mpt{env, issuer};
            mpt.create(
                {.transferFee = 1,
                 .flags = tfMPTCanTransfer |
                     tfMPTCanHoldConfidentialBalance,
                 .err = temBAD_TRANSFER_FEE});
        }
        {
            Env env{*this, features()};
            MPTTester mpt{env, issuer};
            mpt.create(
                {.flags = tfMPTCanTransfer |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuance =
                env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(issuance);
            BEAST_EXPECT(
                issuance->isFlag(
                    lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(
                (issuance->getFieldU32(sfMutableFlags) &
                 lsmfMPTCanMutateCanHoldConfidentialBalance) ==
                0u);
        }
    }

    void
    testEnableAndRegisterKeys()
    {
        testcase("enable confidential issuance and register keys");
        using namespace jtx;
        Account const issuer{"issuer"};
        Env env{*this, features()};
        MPTTester mpt{env, issuer};
        mpt.create({.flags = tfMPTCanTransfer});

        auto issuance = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(issuance);
        BEAST_EXPECT(
            (issuance->getFieldU32(sfMutableFlags) &
             lsmfMPTCanMutateCanHoldConfidentialBalance) != 0u);

        auto const issuerKey = publicKey();
        auto const auditorKey = publicKey();
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = issuerKey,
             .auditorEncryptionKey = auditorKey});

        issuance = env.le(keylet::mptIssuance(mpt.issuanceID()));
        BEAST_EXPECT(
            issuance->isFlag(
                lsfMPTCanHoldConfidentialBalance));
        BEAST_EXPECT(
            issuance->getFieldVL(sfIssuerEncryptionKey) ==
            Blob{issuerKey.begin(), issuerKey.end()});
        BEAST_EXPECT(
            issuance->getFieldVL(sfAuditorEncryptionKey) ==
            Blob{auditorKey.begin(), auditorKey.end()});

        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .err = tecNO_PERMISSION});
        mpt.set(
            {.issuerEncryptionKey = publicKey(),
             .err = tecNO_PERMISSION});
        mpt.set(
            {.transferFee = 1, .err = tecNO_PERMISSION});
    }

    void
    testKeyValidation()
    {
        testcase("confidential issuance key validation");
        using namespace jtx;
        Account const issuer{"issuer"};
        Env env{*this, features()};
        MPTTester mpt{env, issuer};
        mpt.create({.flags = tfMPTCanTransfer});

        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .auditorEncryptionKey = publicKey(),
             .err = temMALFORMED});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = std::string(33, '\0'),
             .err = temMALFORMED});
    }

public:
    void
    run() override
    {
        testCreate();
        testEnableAndRegisterKeys();
        testKeyValidation();
    }
};

BEAST_DEFINE_TESTSUITE(
    ConfidentialMPT,
    app,
    xrpl);

}  // namespace xrpl::test
