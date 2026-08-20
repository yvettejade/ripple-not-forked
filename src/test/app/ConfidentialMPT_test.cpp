#include <test/jtx/Env.h>
#include <test/jtx/Account.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>
#include <test/jtx/txflags.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>

namespace xrpl {

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    static constexpr char const* kGenerator =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    void
    testIssuanceConfiguration(FeatureBitset const& features)
    {
        using namespace test::jtx;
        testcase("issuance configuration");

        Account const issuer{"issuer"};

        {
            Env env(*this, features);
            MPTTester tester(env, issuer);
            tester.create(
                {.transferFee = 1,
                 .flags =
                     tfMPTCanTransfer |
                     tfMPTCanHoldConfidentialBalance,
                 .err = temBAD_TRANSFER_FEE});
        }

        {
            Env env(*this, features - featureConfidentialTransfer);
            MPTTester tester(env, issuer);
            tester.create(
                {.flags = tfMPTCanHoldConfidentialBalance,
                 .err = temDISABLED});
        }

        {
            Env env(*this, features);
            MPTTester tester(env, issuer);
            tester.create(
                {.flags =
                     tfMPTCanTransfer |
                     tfMPTCanHoldConfidentialBalance});

            json::Value set;
            set[sfAccount] = issuer.human();
            set[sfTransactionType] = jss::MPTokenIssuanceSet;
            set[sfMPTokenIssuanceID] =
                to_string(tester.issuanceID());
            set[sfFlags] = tfMPTSetCanHoldConfidentialBalance;
            set[sfIssuerEncryptionKey] = kGenerator;
            env(set);
            env.close();

            auto const issuance =
                env.le(keylet::mptIssuance(tester.issuanceID()));
            BEAST_EXPECT(issuance);
            BEAST_EXPECT(
                issuance->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(
                issuance->at(sfIssuerEncryptionKey).size() == 33);
            BEAST_EXPECT(
                issuance->at(sfConfidentialOutstandingAmount) == 0);
        }
    }

    void
    testMalformedTransactions(FeatureBitset const& features)
    {
        using namespace test::jtx;
        testcase("malformed confidential transactions");

        Env env(*this, features);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(1000), alice, bob);

        json::Value send;
        send[sfAccount] = alice.human();
        send[sfDestination] = bob.human();
        send[sfTransactionType] = "ConfidentialMPTSend";
        send[sfMPTokenIssuanceID] =
            to_string(makeMptID(env.seq(alice), alice));
        send[sfSenderEncryptedAmount] = "00";
        send[sfDestinationEncryptedAmount] = "00";
        send[sfIssuerEncryptedAmount] = "00";
        send[sfBalanceCommitment] = kGenerator;
        send[sfAmountCommitment] = kGenerator;
        send[sfZKProof] = strHex(std::string(946, '\0'));
        env(send, Ter(temBAD_CIPHERTEXT));
    }

public:
    void
    run() override
    {
        auto const features = test::jtx::testableAmendments();
        testIssuanceConfiguration(features);
        testMalformedTransactions(features);
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, app, xrpl);

}  // namespace xrpl
