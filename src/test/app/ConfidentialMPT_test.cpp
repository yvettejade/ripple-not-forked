#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/fee.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>
#include <test/jtx/txflags.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/confidential/ElGamal.h>
#include <xrpl/crypto/confidential/Proofs.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTUtils.h>

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <string>

namespace xrpl {

using namespace crypto::confidential;

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    static constexpr char const* kGenerator =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    static secp256k1_context const*
    secpCtx()
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

    static Scalar
    scalar(std::uint8_t value)
    {
        Scalar out{};
        out.back() = value;
        return out;
    }

    static bool
    publicKey(Scalar const& sk, CompressedPoint& pk)
    {
        secp256k1_pubkey pub;
        if (secp256k1_ec_pubkey_create(secpCtx(), &pub, sk.data()) != 1)
            return false;
        std::size_t len = pk.size();
        return secp256k1_ec_pubkey_serialize(
                   secpCtx(), pk.data(), &len, &pub, SECP256K1_EC_COMPRESSED) ==
            1 &&
            len == pk.size();
    }

    static std::string
    hex(CompressedPoint const& point)
    {
        return strHex(point);
    }

    static std::string
    hex(Scalar const& value)
    {
        return strHex(value);
    }

    static std::string
    hex(Ciphertext const& ciphertext)
    {
        CiphertextBlob blob{};
        if (!serializeCiphertext(ciphertext, blob))
            return {};
        return strHex(blob);
    }

    static std::string
    hex(SchnorrProof const& proof)
    {
        return strHex(proof);
    }

    static std::string
    dummyProof(std::size_t bytes)
    {
        return strHex(std::string(bytes, '\x01'));
    }

    static std::string
    validCiphertextHex()
    {
        return std::string(kGenerator) + kGenerator;
    }

    test::jtx::Fee
    proofFee(test::jtx::Env& env)
    {
        return test::jtx::Fee{static_cast<std::uint64_t>(
            env.current()->fees().base.drops() * 10)};
    }

    json::Value
    convertTx(
        test::jtx::Account const& account,
        MPTID const& id,
        std::uint64_t amount,
        CompressedPoint const& holderPk,
        Ciphertext const& holderCt,
        Ciphertext const& issuerCt,
        Scalar const& blinding,
        SchnorrProof const& proof)
    {
        json::Value jv;
        jv[sfAccount] = account.human();
        jv[sfTransactionType] = "ConfidentialMPTConvert";
        jv[sfMPTokenIssuanceID] = to_string(id);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptionKey] = hex(holderPk);
        jv[sfHolderEncryptedAmount] = hex(holderCt);
        jv[sfIssuerEncryptedAmount] = hex(issuerCt);
        jv[sfBlindingFactor] = hex(blinding);
        jv[sfZKProof] = hex(proof);
        return jv;
    }

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
                     tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance,
                 .err = temBAD_TRANSFER_FEE});
        }

        {
            Env env(*this, features - featureConfidentialTransfer);
            MPTTester tester(env, issuer);
            tester.create(
                {.flags = tfMPTCanHoldConfidentialBalance, .err = temDISABLED});
        }

        {
            Env env(*this, features);
            MPTTester tester(env, issuer);
            tester.create(
                {.flags =
                     tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});

            json::Value set;
            set[sfAccount] = issuer.human();
            set[sfTransactionType] = jss::MPTokenIssuanceSet;
            set[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
            set[sfFlags] = tfMPTSetCanHoldConfidentialBalance;
            set[sfIssuerEncryptionKey] = kGenerator;
            env(set);
            env.close();

            auto const issuance =
                env.le(keylet::mptIssuance(tester.issuanceID()));
            BEAST_EXPECT(issuance);
            BEAST_EXPECT(issuance->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(issuance->at(sfIssuerEncryptionKey).size() == 33);
            BEAST_EXPECT(issuance->at(sfConfidentialOutstandingAmount) == 0);
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
        send[sfZKProof] = dummyProof(946);
        env(send, proofFee(env), ter(temBAD_CIPHERTEXT));

        send[sfSenderEncryptedAmount] = validCiphertextHex();
        send[sfDestinationEncryptedAmount] = validCiphertextHex();
        send[sfIssuerEncryptedAmount] = validCiphertextHex();
        send[sfAccount] = alice.human();
        send[sfDestination] = alice.human();
        env(send, proofFee(env), ter(temMALFORMED));
    }

    void
    testConvertMergeClawback(FeatureBitset const& features)
    {
        using namespace test::jtx;
        testcase("convert merge clawback");

        Env env(*this, features);
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        MPTTester tester(
            env,
            issuer,
            {.holders = {alice},
             .create = {
                 .pay = std::pair<std::vector<Account>, std::uint64_t>{
                     {alice}, 1'000},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance |
                     tfMPTCanClawback}});

        auto const issuerSk = scalar(1);
        CompressedPoint issuerPk{};
        BEAST_EXPECT(publicKey(issuerSk, issuerPk));

        json::Value set;
        set[sfAccount] = issuer.human();
        set[sfTransactionType] = jss::MPTokenIssuanceSet;
        set[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        set[sfIssuerEncryptionKey] = hex(issuerPk);
        env(set);
        env.close();

        auto const holderSk = scalar(2);
        CompressedPoint holderPk{};
        BEAST_EXPECT(publicKey(holderSk, holderPk));
        auto const blinding = scalar(4);
        Ciphertext holderCt{};
        Ciphertext issuerCt{};
        BEAST_EXPECT(encrypt(holderPk, 50, blinding, holderCt));
        BEAST_EXPECT(encrypt(issuerPk, 50, blinding, issuerCt));

        auto const extra = confidential_mpt::proofContext(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            alice.id(),
            tester.issuanceID(),
            0);
        SchnorrProof pok{};
        BEAST_EXPECT(createSchnorrProofOfKnowledge(
            holderSk, holderPk, pok, makeSlice(extra)));

        env(convertTx(
                alice,
                tester.issuanceID(),
                50,
                holderPk,
                holderCt,
                issuerCt,
                blinding,
                pok),
            proofFee(env));
        env.close();

        auto const token = env.le(keylet::mptoken(tester.issuanceID(), alice.id()));
        auto const issuance = env.le(keylet::mptIssuance(tester.issuanceID()));
        BEAST_EXPECT(token);
        BEAST_EXPECT(issuance);
        BEAST_EXPECT(token->at(sfMPTAmount) == 950);
        BEAST_EXPECT(issuance->at(sfConfidentialOutstandingAmount) == 50);
        BEAST_EXPECT(issuance->at(sfOutstandingAmount) == 1'000);
        BEAST_EXPECT(token->at(sfConfidentialBalanceVersion) == 0);

        Ciphertext spending{};
        Ciphertext expectedZero{};
        BEAST_EXPECT(parseCiphertext(
            makeSlice(token->getFieldVL(sfConfidentialBalanceSpending)),
            spending));
        BEAST_EXPECT(canonicalEncryptedZero(
            {alice.id().data(), alice.id().size()},
            {tester.issuanceID().data(), tester.issuanceID().size()},
            holderPk,
            expectedZero));
        BEAST_EXPECT(spending.R == expectedZero.R);
        BEAST_EXPECT(spending.S == expectedZero.S);

        json::Value merge;
        merge[sfAccount] = alice.human();
        merge[sfTransactionType] = "ConfidentialMPTMergeInbox";
        merge[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        env(merge, proofFee(env));
        env.close();

        auto const merged = env.le(keylet::mptoken(tester.issuanceID(), alice.id()));
        BEAST_EXPECT(merged);
        BEAST_EXPECT(merged->at(sfConfidentialBalanceVersion) == 1);
        Ciphertext inbox{};
        BEAST_EXPECT(parseCiphertext(
            makeSlice(merged->getFieldVL(sfConfidentialBalanceInbox)), inbox));
        BEAST_EXPECT(inbox.R == expectedZero.R);
        BEAST_EXPECT(inbox.S == expectedZero.S);

        Ciphertext issuerMirror{};
        BEAST_EXPECT(parseCiphertext(
            makeSlice(merged->getFieldVL(sfIssuerEncryptedBalance)),
            issuerMirror));
        auto const clawExtra = confidential_mpt::proofContext(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
            alice.id(),
            tester.issuanceID(),
            merged->at(sfConfidentialBalanceVersion));
        SchnorrProof claw{};
        BEAST_EXPECT(createClawbackProof(
            issuerSk, issuerPk, issuerMirror, 50, claw, makeSlice(clawExtra)));

        json::Value clawback;
        clawback[sfAccount] = issuer.human();
        clawback[sfTransactionType] = "ConfidentialMPTClawback";
        clawback[sfHolder] = alice.human();
        clawback[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        clawback[sfMPTAmount] = "50";
        clawback[sfZKProof] = hex(claw);
        env(clawback, proofFee(env));
        env.close();

        auto const after =
            env.le(keylet::mptoken(tester.issuanceID(), alice.id()));
        auto const issuanceAfter =
            env.le(keylet::mptIssuance(tester.issuanceID()));
        BEAST_EXPECT(after);
        BEAST_EXPECT(issuanceAfter);
        BEAST_EXPECT(after->at(sfMPTAmount) == 950);
        BEAST_EXPECT(issuanceAfter->at(sfConfidentialOutstandingAmount) == 0);
        BEAST_EXPECT(issuanceAfter->at(sfOutstandingAmount) == 950);
        BEAST_EXPECT(after->at(sfConfidentialBalanceVersion) == 2);
    }

    void
    testConvertBackAndSendFailClosed(FeatureBitset const& features)
    {
        using namespace test::jtx;
        testcase("convertback and send fail closed");

        Env env(*this, features);
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        MPTTester tester(
            env,
            issuer,
            {.holders = {alice, bob},
             .create = {
                 .pay = std::pair<std::vector<Account>, std::uint64_t>{
                     {alice, bob}, 500},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance}});

        auto const issuerSk = scalar(1);
        CompressedPoint issuerPk{};
        BEAST_EXPECT(publicKey(issuerSk, issuerPk));
        json::Value set;
        set[sfAccount] = issuer.human();
        set[sfTransactionType] = jss::MPTokenIssuanceSet;
        set[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        set[sfIssuerEncryptionKey] = hex(issuerPk);
        env(set);
        env.close();

        auto const aliceSk = scalar(2);
        auto const bobSk = scalar(3);
        CompressedPoint alicePk{};
        CompressedPoint bobPk{};
        BEAST_EXPECT(publicKey(aliceSk, alicePk));
        BEAST_EXPECT(publicKey(bobSk, bobPk));
        auto const blinding = scalar(5);
        Ciphertext aliceCt{};
        Ciphertext issuerCt{};
        Ciphertext bobCt{};
        Ciphertext bobIssuerCt{};
        BEAST_EXPECT(encrypt(alicePk, 40, blinding, aliceCt));
        BEAST_EXPECT(encrypt(issuerPk, 40, blinding, issuerCt));
        auto const bobBlind = scalar(6);
        BEAST_EXPECT(encrypt(bobPk, 0, bobBlind, bobCt));
        BEAST_EXPECT(encrypt(issuerPk, 0, bobBlind, bobIssuerCt));

        auto const aliceExtra = confidential_mpt::proofContext(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            alice.id(),
            tester.issuanceID(),
            0);
        auto const bobExtra = confidential_mpt::proofContext(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            bob.id(),
            tester.issuanceID(),
            0);
        SchnorrProof alicePok{};
        SchnorrProof bobPok{};
        BEAST_EXPECT(createSchnorrProofOfKnowledge(
            aliceSk, alicePk, alicePok, makeSlice(aliceExtra)));
        BEAST_EXPECT(createSchnorrProofOfKnowledge(
            bobSk, bobPk, bobPok, makeSlice(bobExtra)));

        env(convertTx(
                alice,
                tester.issuanceID(),
                40,
                alicePk,
                aliceCt,
                issuerCt,
                blinding,
                alicePok),
            proofFee(env));
        env(convertTx(
                bob, tester.issuanceID(), 0, bobPk, bobCt, bobIssuerCt, bobBlind, bobPok),
            proofFee(env));
        env.close();

        json::Value merge;
        merge[sfAccount] = alice.human();
        merge[sfTransactionType] = "ConfidentialMPTMergeInbox";
        merge[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        env(merge, proofFee(env));
        env.close();

        Ciphertext backCt{};
        Ciphertext backIssuer{};
        auto const backBlind = scalar(7);
        BEAST_EXPECT(encrypt(alicePk, 10, backBlind, backCt));
        BEAST_EXPECT(encrypt(issuerPk, 10, backBlind, backIssuer));
        json::Value convertBack;
        convertBack[sfAccount] = alice.human();
        convertBack[sfTransactionType] = "ConfidentialMPTConvertBack";
        convertBack[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        convertBack[sfMPTAmount] = "10";
        convertBack[sfHolderEncryptedAmount] = hex(backCt);
        convertBack[sfIssuerEncryptedAmount] = hex(backIssuer);
        convertBack[sfBlindingFactor] = hex(backBlind);
        convertBack[sfBalanceCommitment] = kGenerator;
        convertBack[sfZKProof] = dummyProof(816);
        env(convertBack, proofFee(env), ter(tecBAD_PROOF));

        json::Value send;
        send[sfAccount] = alice.human();
        send[sfDestination] = bob.human();
        send[sfTransactionType] = "ConfidentialMPTSend";
        send[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        send[sfSenderEncryptedAmount] = validCiphertextHex();
        send[sfDestinationEncryptedAmount] = validCiphertextHex();
        send[sfIssuerEncryptedAmount] = validCiphertextHex();
        send[sfBalanceCommitment] = kGenerator;
        send[sfAmountCommitment] = kGenerator;
        send[sfZKProof] = dummyProof(946);
        env(send, proofFee(env), ter(tecBAD_PROOF));

        send[sfAccount] = issuer.human();
        env(send, proofFee(env), ter(temMALFORMED));
    }

    void
    testProofFee(FeatureBitset const& features)
    {
        using namespace test::jtx;
        testcase("ten times base fee");

        Env env(*this, features);
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        MPTTester tester(
            env,
            issuer,
            {.holders = {alice},
             .create = {
                 .pay = std::pair<std::vector<Account>, std::uint64_t>{
                     {alice}, 100},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance}});

        json::Value set;
        set[sfAccount] = issuer.human();
        set[sfTransactionType] = jss::MPTokenIssuanceSet;
        set[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        set[sfIssuerEncryptionKey] = kGenerator;
        env(set);
        env.close();

        json::Value merge;
        merge[sfAccount] = alice.human();
        merge[sfTransactionType] = "ConfidentialMPTMergeInbox";
        merge[sfMPTokenIssuanceID] = to_string(tester.issuanceID());
        env(merge,
            Fee{static_cast<std::uint64_t>(env.current()->fees().base.drops())},
            ter(telINSUF_FEE_P));
    }

public:
    void
    run() override
    {
        auto const features = test::jtx::testableAmendments();
        testIssuanceConfiguration(features);
        testMalformedTransactions(features);
        testConvertMergeClawback(features);
        testConvertBackAndSendFailClosed(features);
        testProofFee(features);
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, app, xrpl);

}  // namespace xrpl
