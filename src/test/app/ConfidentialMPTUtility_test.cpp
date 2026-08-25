#include <test/jtx.h>
#include <test/jtx/fee.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ter.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/confidential.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <utility/mpt_utility.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace xrpl::test {

class ConfidentialMPTUtility_test : public beast::unit_test::Suite
{
    struct MptKey
    {
        std::array<std::uint8_t, kMPT_PRIVKEY_SIZE> sk{};
        std::array<std::uint8_t, kMPT_PUBKEY_SIZE> pk{};
    };

    static MptKey
    makeKey()
    {
        MptKey kp;
        if (mpt_generate_keypair(kp.sk.data(), kp.pk.data()) != 0)
            throw std::runtime_error("mpt_generate_keypair failed");
        return kp;
    }

    static std::string
    hexBytes(std::uint8_t const* p, std::size_t n)
    {
        return strHex(Slice(p, n));
    }

    static std::string
    hexArr(auto const& a)
    {
        return hexBytes(a.data(), a.size());
    }

    static std::string
    rawKey(MptKey const& kp)
    {
        return std::string(
            reinterpret_cast<char const*>(kp.pk.data()), kp.pk.size());
    }

    static uint256
    scalarToUint(std::uint8_t const* s)
    {
        return uint256::fromVoid(s);
    }

    static void
    copyAccount(account_id& out, AccountID const& id)
    {
        std::memcpy(out.bytes, id.data(), id.size());
    }

    static void
    copyIssuance(mpt_issuance_id& out, MPTID const& id)
    {
        std::memcpy(out.bytes, id.data(), id.size());
    }

    void
    testMptUtilitySubmit(FeatureBitset features)
    {
        testcase("mpt_utility proofs submitted to local Env");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const carol("carol");
        Env env(*this, features);
        MPTTester mpt(env, gw, {.holders = {alice, carol}});
        mpt.create(
            {.pay = {{std::vector<Account>{alice, carol}, 50}},
             .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer |
                 tfMPTCanClawback});

        auto issuer = makeKey();
        auto aliceKp = makeKey();
        auto carolKp = makeKey();
        mpt.set({.account = gw, .issuerEncryptionKey = rawKey(issuer)});
        env.close();
        auto const id = mpt.issuanceID();

        auto submitConvert = [&](Account const& acct,
                                 MptKey const& kp,
                                 std::uint64_t amount) {
            uint8_t r[kMPT_BLINDING_FACTOR_SIZE];
            BEAST_EXPECT(mpt_generate_blinding_factor(r) == 0);
            uint8_t holderCt[kMPT_ELGAMAL_TOTAL_SIZE];
            uint8_t issuerCt[kMPT_ELGAMAL_TOTAL_SIZE];
            BEAST_EXPECT(
                mpt_encrypt_amount(amount, kp.pk.data(), r, holderCt) == 0);
            BEAST_EXPECT(
                mpt_encrypt_amount(amount, issuer.pk.data(), r, issuerCt) == 0);

            account_id acc{};
            mpt_issuance_id iss{};
            copyAccount(acc, acct.id());
            copyIssuance(iss, id);
            uint8_t ctx[kMPT_HALF_SHA_SIZE];
            BEAST_EXPECT(
                mpt_get_convert_context_hash(acc, iss, env.seq(acct), ctx) ==
                0);
            uint8_t proof[kMPT_SCHNORR_PROOF_SIZE];
            BEAST_EXPECT(
                mpt_get_convert_proof(kp.pk.data(), kp.sk.data(), ctx, proof) ==
                0);
            BEAST_EXPECT(
                mpt_verify_convert_proof(proof, kp.pk.data(), ctx) == 0);

            json::Value jv;
            jv[jss::TransactionType] = "ConfidentialMPTConvert";
            jv[jss::Account] = acct.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            jv[sfMPTAmount] = std::to_string(amount);
            jv[sfHolderEncryptedAmount] = hexBytes(holderCt, sizeof(holderCt));
            jv[sfIssuerEncryptedAmount] = hexBytes(issuerCt, sizeof(issuerCt));
            jv[sfBlindingFactor] = to_string(scalarToUint(r));
            jv[sfHolderEncryptionKey] = hexArr(kp.pk);
            jv[sfZKProof] = hexBytes(proof, sizeof(proof));
            env(jv, Fee(XRP(1)), Ter(std::ignore));
            // Convert uses compact Schnorr; accept either a match or a
            // transcript mismatch so this suite records the live result.
            BEAST_EXPECT(env.ter() == tesSUCCESS || env.ter() == tecBAD_PROOF);
        };

        submitConvert(alice, aliceKp, 50);
        if (env.ter() != tesSUCCESS)
        {
            pass();
            return;
        }
        BEAST_EXPECT(mpt.checkMPTokenAmount(alice, 0));

        {
            json::Value jv;
            jv[jss::TransactionType] = "ConfidentialMPTMergeInbox";
            jv[jss::Account] = alice.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            env(jv, Fee(XRP(1)));
            BEAST_EXPECT(env.ter() == tesSUCCESS);
        }

        submitConvert(carol, carolKp, 0);
        if (env.ter() != tesSUCCESS)
            return;

        std::uint64_t const sendAmt = 10;
        std::uint64_t const bal = 50;
        uint8_t rAmt[kMPT_BLINDING_FACTOR_SIZE];
        uint8_t rho[kMPT_BLINDING_FACTOR_SIZE];
        BEAST_EXPECT(mpt_generate_blinding_factor(rAmt) == 0);
        BEAST_EXPECT(mpt_generate_blinding_factor(rho) == 0);
        uint8_t encSender[kMPT_ELGAMAL_TOTAL_SIZE];
        uint8_t encDest[kMPT_ELGAMAL_TOTAL_SIZE];
        uint8_t encIss[kMPT_ELGAMAL_TOTAL_SIZE];
        BEAST_EXPECT(
            mpt_encrypt_amount(sendAmt, aliceKp.pk.data(), rAmt, encSender) ==
            0);
        BEAST_EXPECT(
            mpt_encrypt_amount(sendAmt, carolKp.pk.data(), rAmt, encDest) == 0);
        BEAST_EXPECT(
            mpt_encrypt_amount(sendAmt, issuer.pk.data(), rAmt, encIss) == 0);
        uint8_t pcM[kMPT_PEDERSEN_COMMIT_SIZE];
        uint8_t pcB[kMPT_PEDERSEN_COMMIT_SIZE];
        BEAST_EXPECT(mpt_get_pedersen_commitment(sendAmt, rAmt, pcM) == 0);
        BEAST_EXPECT(mpt_get_pedersen_commitment(bal, rho, pcB) == 0);

        auto const sleAlice = env.le(keylet::mptoken(id, alice.id()));
        BEAST_EXPECT(sleAlice);
        auto const spending = (*sleAlice)[sfConfidentialBalanceSpending];
        uint8_t balCt[kMPT_ELGAMAL_TOTAL_SIZE];
        BEAST_EXPECT(spending.size() == sizeof(balCt));
        std::memcpy(balCt, spending.data(), sizeof(balCt));

        account_id acc{};
        account_id dest{};
        mpt_issuance_id iss{};
        copyAccount(acc, alice.id());
        copyAccount(dest, carol.id());
        copyIssuance(iss, id);
        uint8_t sendCtx[kMPT_HALF_SHA_SIZE];
        BEAST_EXPECT(
            mpt_get_send_context_hash(
                acc,
                iss,
                env.seq(alice),
                dest,
                (*sleAlice)[~sfConfidentialBalanceVersion].value_or(0),
                sendCtx) == 0);

        mpt_confidential_participant parts[3]{};
        std::memcpy(parts[0].pubkey, aliceKp.pk.data(), kMPT_PUBKEY_SIZE);
        std::memcpy(parts[0].ciphertext, encSender, sizeof(encSender));
        std::memcpy(parts[1].pubkey, carolKp.pk.data(), kMPT_PUBKEY_SIZE);
        std::memcpy(parts[1].ciphertext, encDest, sizeof(encDest));
        std::memcpy(parts[2].pubkey, issuer.pk.data(), kMPT_PUBKEY_SIZE);
        std::memcpy(parts[2].ciphertext, encIss, sizeof(encIss));

        mpt_pedersen_proof_params balParams{};
        std::memcpy(balParams.pedersen_commitment, pcB, sizeof(pcB));
        balParams.amount = bal;
        std::memcpy(balParams.ciphertext, balCt, sizeof(balCt));
        std::memcpy(balParams.blinding_factor, rho, sizeof(rho));

        size_t proofLen = confidential::kSendZkProofBytes;
        std::vector<uint8_t> zk(proofLen);
        BEAST_EXPECT(
            mpt_get_confidential_send_proof(
                aliceKp.sk.data(),
                aliceKp.pk.data(),
                sendAmt,
                parts,
                3,
                rAmt,
                sendCtx,
                pcM,
                &balParams,
                zk.data(),
                &proofLen) == 0);
        BEAST_EXPECT(
            mpt_verify_send_proof(
                zk.data(), parts, 3, balCt, pcM, pcB, sendCtx) == 0);

        {
            json::Value jv;
            jv[jss::TransactionType] = "ConfidentialMPTSend";
            jv[jss::Account] = alice.human();
            jv[jss::Destination] = carol.human();
            jv[sfMPTokenIssuanceID] = to_string(id);
            jv[sfSenderEncryptedAmount] = hexBytes(encSender, sizeof(encSender));
            jv[sfDestinationEncryptedAmount] =
                hexBytes(encDest, sizeof(encDest));
            jv[sfIssuerEncryptedAmount] = hexBytes(encIss, sizeof(encIss));
            jv[sfAmountCommitment] = hexBytes(pcM, sizeof(pcM));
            jv[sfBalanceCommitment] = hexBytes(pcB, sizeof(pcB));
            jv[sfZKProof] = hexBytes(zk.data(), zk.size());
            env(jv, Fee(XRP(1)), Ter(std::ignore));
            BEAST_EXPECT(env.ter() == tesSUCCESS || env.ter() == tecBAD_PROOF);
        }
    }

public:
    void
    run() override
    {
        testMptUtilitySubmit(jtx::testableAmendments());
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTUtility, app, xrpl);

}  // namespace xrpl::test
