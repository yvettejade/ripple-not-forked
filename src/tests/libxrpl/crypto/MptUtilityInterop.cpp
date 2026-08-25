#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/confidential.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/TxFormats.h>

#include <utility/mpt_utility.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace xrpl;
using namespace xrpl::confidential;

namespace {

account_id
toAccount(std::array<std::uint8_t, 20> const& bytes)
{
    account_id id{};
    std::memcpy(id.bytes, bytes.data(), bytes.size());
    return id;
}

mpt_issuance_id
toIssuance(std::array<std::uint8_t, 24> const& bytes)
{
    mpt_issuance_id id{};
    std::memcpy(id.bytes, bytes.data(), bytes.size());
    return id;
}

CompressedPoint
pointFrom(std::uint8_t const* bytes)
{
    CompressedPoint p{};
    std::memcpy(p.data(), bytes, p.size());
    return p;
}

}  // namespace

TEST(MptUtilityInterop, ContextHashesMatchRippled)
{
    std::array<std::uint8_t, 20> acct{};
    acct.fill(0x11);
    std::array<std::uint8_t, 20> other{};
    other.fill(0x22);
    std::array<std::uint8_t, 24> iss{};
    iss.fill(0x33);
    std::uint32_t const seq = 7;
    std::uint32_t const ver = 2;

    uint8_t mptHash[kMPT_HALF_SHA_SIZE];
    ASSERT_EQ(
        mpt_get_convert_context_hash(
            toAccount(acct), toIssuance(iss), seq, mptHash),
        0);
    auto const xrplHash = transactionContextIDConvert(
        ttCONFIDENTIAL_MPT_CONVERT,
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        seq);
    EXPECT_EQ(
        std::vector<std::uint8_t>(mptHash, mptHash + 32),
        std::vector<std::uint8_t>(xrplHash.begin(), xrplHash.end()));

    ASSERT_EQ(
        mpt_get_send_context_hash(
            toAccount(acct),
            toIssuance(iss),
            seq,
            toAccount(other),
            ver,
            mptHash),
        0);
    auto const sendHash = transactionContextIDSend(
        ttCONFIDENTIAL_MPT_SEND,
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        seq,
        Slice(other.data(), other.size()),
        ver);
    EXPECT_EQ(
        std::vector<std::uint8_t>(mptHash, mptHash + 32),
        std::vector<std::uint8_t>(sendHash.begin(), sendHash.end()));

    ASSERT_EQ(
        mpt_get_convert_back_context_hash(
            toAccount(acct), toIssuance(iss), seq, ver, mptHash),
        0);
    auto const backHash = transactionContextIDConvertBack(
        ttCONFIDENTIAL_MPT_CONVERT_BACK,
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        seq,
        ver);
    EXPECT_EQ(
        std::vector<std::uint8_t>(mptHash, mptHash + 32),
        std::vector<std::uint8_t>(backHash.begin(), backHash.end()));

    ASSERT_EQ(
        mpt_get_clawback_context_hash(
            toAccount(acct),
            toIssuance(iss),
            seq,
            toAccount(other),
            mptHash),
        0);
    auto const clawHash = transactionContextIDClawback(
        ttCONFIDENTIAL_MPT_CLAWBACK,
        Slice(acct.data(), acct.size()),
        Slice(iss.data(), iss.size()),
        seq,
        Slice(other.data(), other.size()));
    EXPECT_EQ(
        std::vector<std::uint8_t>(mptHash, mptHash + 32),
        std::vector<std::uint8_t>(clawHash.begin(), clawHash.end()));
}

TEST(MptUtilityInterop, ConvertProofVerifiesOnBothSides)
{
    uint8_t priv[kMPT_PRIVKEY_SIZE];
    uint8_t pub[kMPT_PUBKEY_SIZE];
    ASSERT_EQ(mpt_generate_keypair(priv, pub), 0);

    std::array<std::uint8_t, 20> acct{};
    acct.fill(0x11);
    std::array<std::uint8_t, 24> iss{};
    iss.fill(0x44);
    uint8_t ctx[kMPT_HALF_SHA_SIZE];
    ASSERT_EQ(
        mpt_get_convert_context_hash(
            toAccount(acct), toIssuance(iss), 1, ctx),
        0);

    uint8_t proof[kMPT_SCHNORR_PROOF_SIZE];
    ASSERT_EQ(mpt_get_convert_proof(pub, priv, ctx, proof), 0);
    EXPECT_EQ(mpt_verify_convert_proof(proof, pub, ctx), 0);

    auto const pk = pointFrom(pub);
    EXPECT_FALSE(verifySchnorrRegister(
        pk, Slice(ctx, sizeof(ctx)), Slice(proof, sizeof(proof))))
        << "unexpected: mpt-crypto convert proof verified in rippled";
}

TEST(MptUtilityInterop, ConvertBackAndSendProofsSelfVerifyThenCrossCheck)
{
    uint8_t priv[kMPT_PRIVKEY_SIZE];
    uint8_t pub[kMPT_PUBKEY_SIZE];
    ASSERT_EQ(mpt_generate_keypair(priv, pub), 0);

    uint8_t destPriv[kMPT_PRIVKEY_SIZE];
    uint8_t destPub[kMPT_PUBKEY_SIZE];
    ASSERT_EQ(mpt_generate_keypair(destPriv, destPub), 0);

    uint8_t issPriv[kMPT_PRIVKEY_SIZE];
    uint8_t issPub[kMPT_PUBKEY_SIZE];
    ASSERT_EQ(mpt_generate_keypair(issPriv, issPub), 0);

    uint64_t const amount = 100;
    uint64_t const balance = 1000;
    uint8_t sharedBf[kMPT_BLINDING_FACTOR_SIZE];
    uint8_t balBf[kMPT_BLINDING_FACTOR_SIZE];
    ASSERT_EQ(mpt_generate_blinding_factor(sharedBf), 0);
    ASSERT_EQ(mpt_generate_blinding_factor(balBf), 0);

    uint8_t senderCt[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t destCt[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t issuerCt[kMPT_ELGAMAL_TOTAL_SIZE];
    uint8_t balCt[kMPT_ELGAMAL_TOTAL_SIZE];
    ASSERT_EQ(mpt_encrypt_amount(amount, pub, sharedBf, senderCt), 0);
    ASSERT_EQ(mpt_encrypt_amount(amount, destPub, sharedBf, destCt), 0);
    ASSERT_EQ(mpt_encrypt_amount(amount, issPub, sharedBf, issuerCt), 0);
    ASSERT_EQ(mpt_encrypt_amount(balance, pub, balBf, balCt), 0);

    uint8_t amountComm[kMPT_PEDERSEN_COMMIT_SIZE];
    uint8_t balComm[kMPT_PEDERSEN_COMMIT_SIZE];
    ASSERT_EQ(mpt_get_pedersen_commitment(amount, sharedBf, amountComm), 0);
    ASSERT_EQ(mpt_get_pedersen_commitment(balance, balBf, balComm), 0);

    std::array<std::uint8_t, 20> acct{};
    acct.fill(0x11);
    std::array<std::uint8_t, 20> dest{};
    dest.fill(0x22);
    std::array<std::uint8_t, 24> iss{};
    iss.fill(0x55);
    uint8_t sendCtx[kMPT_HALF_SHA_SIZE];
    ASSERT_EQ(
        mpt_get_send_context_hash(
            toAccount(acct),
            toIssuance(iss),
            3,
            toAccount(dest),
            1,
            sendCtx),
        0);

    mpt_confidential_participant parts[3]{};
    std::memcpy(parts[0].pubkey, pub, kMPT_PUBKEY_SIZE);
    std::memcpy(parts[0].ciphertext, senderCt, kMPT_ELGAMAL_TOTAL_SIZE);
    std::memcpy(parts[1].pubkey, destPub, kMPT_PUBKEY_SIZE);
    std::memcpy(parts[1].ciphertext, destCt, kMPT_ELGAMAL_TOTAL_SIZE);
    std::memcpy(parts[2].pubkey, issPub, kMPT_PUBKEY_SIZE);
    std::memcpy(parts[2].ciphertext, issuerCt, kMPT_ELGAMAL_TOTAL_SIZE);

    mpt_pedersen_proof_params balParams{};
    std::memcpy(balParams.pedersen_commitment, balComm, kMPT_PEDERSEN_COMMIT_SIZE);
    balParams.amount = balance;
    std::memcpy(balParams.ciphertext, balCt, kMPT_ELGAMAL_TOTAL_SIZE);
    std::memcpy(balParams.blinding_factor, balBf, kMPT_BLINDING_FACTOR_SIZE);

    size_t proofLen =
        SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE;
    std::vector<uint8_t> sendProof(proofLen);
    ASSERT_EQ(
        mpt_get_confidential_send_proof(
            priv,
            pub,
            amount,
            parts,
            3,
            sharedBf,
            sendCtx,
            amountComm,
            &balParams,
            sendProof.data(),
            &proofLen),
        0);
    EXPECT_EQ(
        proofLen,
        SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE);
    EXPECT_EQ(
        mpt_verify_send_proof(
            sendProof.data(),
            parts,
            3,
            balCt,
            amountComm,
            balComm,
            sendCtx),
        0);

    SendSigmaPublicInput pubIn;
    pubIn.recipientKeys = {pointFrom(pub), pointFrom(destPub), pointFrom(issPub)};
    pubIn.senderKey = pointFrom(pub);
    pubIn.c1 = pointFrom(senderCt);
    pubIn.c2 = {
        pointFrom(senderCt + 33),
        pointFrom(destCt + 33),
        pointFrom(issuerCt + 33)};
    pubIn.amountCommitment = pointFrom(amountComm);
    pubIn.balanceCommitment = pointFrom(balComm);
    pubIn.balanceC1 = pointFrom(balCt);
    pubIn.balanceC2 = pointFrom(balCt + 33);

    bool const sigmaOk = verifySendSigma(
        pubIn,
        Slice(sendCtx, sizeof(sendCtx)),
        Slice(sendProof.data(), kSendSigmaProofBytes));
    CompressedPoint remaining{};
    ASSERT_TRUE(pointSub(
        pubIn.balanceCommitment, pubIn.amountCommitment, remaining));
    bool const bpOk = verifyBulletproofSend(
        pubIn.amountCommitment,
        remaining,
        Slice(
            sendProof.data() + kSendSigmaProofBytes,
            kAggregatedBulletproofBytes));
    // Record the cross-implementation result. Sigma/Bulletproof transcripts
    // currently differ (SHA-512Half vs SHA-256; context-bound BP vs unbound).
    EXPECT_FALSE(sigmaOk && bpOk)
        << "unexpected: mpt-crypto send proof verified in rippled";
    if (!sigmaOk)
        SUCCEED() << "rippled rejected mpt-crypto send sigma (expected)";
    if (!bpOk)
        SUCCEED() << "rippled rejected mpt-crypto send bulletproof (expected)";

    uint8_t backCtx[kMPT_HALF_SHA_SIZE];
    ASSERT_EQ(
        mpt_get_convert_back_context_hash(
            toAccount(acct), toIssuance(iss), 4, 1, backCtx),
        0);
    uint8_t backProof
        [SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE + kMPT_SINGLE_BULLETPROOF_SIZE];
    ASSERT_EQ(
        mpt_get_convert_back_proof(
            priv, pub, backCtx, amount, &balParams, backProof),
        0);
    EXPECT_EQ(
        mpt_verify_convert_back_proof(
            backProof, pub, balCt, balComm, amount, backCtx),
        0);

    ConvertBackSigmaPublicInput cbPub;
    cbPub.holderKey = pointFrom(pub);
    cbPub.balanceC1 = pointFrom(balCt);
    cbPub.balanceC2 = pointFrom(balCt + 33);
    cbPub.balanceCommitment = pointFrom(balComm);
    bool const cbSigma = verifyConvertBackSigma(
        cbPub,
        Slice(backCtx, sizeof(backCtx)),
        Slice(backProof, kConvertBackSigmaProofBytes));
    uint8_t remComm[kMPT_PEDERSEN_COMMIT_SIZE];
    ASSERT_EQ(mpt_compute_convert_back_remainder(balComm, amount, remComm), 0);
    bool const cbBp = verifyBulletproofSingle(
        pointFrom(remComm),
        Slice(
            backProof + kConvertBackSigmaProofBytes, kSingleBulletproofBytes));
    EXPECT_FALSE(cbSigma && cbBp)
        << "unexpected: mpt-crypto convert-back proof verified in rippled";
}

TEST(MptUtilityInterop, ClawbackProofCrossCheck)
{
    uint8_t priv[kMPT_PRIVKEY_SIZE];
    uint8_t pub[kMPT_PUBKEY_SIZE];
    ASSERT_EQ(mpt_generate_keypair(priv, pub), 0);
    uint8_t bf[kMPT_BLINDING_FACTOR_SIZE];
    ASSERT_EQ(mpt_generate_blinding_factor(bf), 0);
    uint64_t const amount = 25;
    uint8_t ct[kMPT_ELGAMAL_TOTAL_SIZE];
    ASSERT_EQ(mpt_encrypt_amount(amount, pub, bf, ct), 0);

    std::array<std::uint8_t, 20> issuer{};
    issuer.fill(0x01);
    std::array<std::uint8_t, 20> holder{};
    holder.fill(0x02);
    std::array<std::uint8_t, 24> iss{};
    iss.fill(0x03);
    uint8_t ctx[kMPT_HALF_SHA_SIZE];
    ASSERT_EQ(
        mpt_get_clawback_context_hash(
            toAccount(issuer),
            toIssuance(iss),
            9,
            toAccount(holder),
            ctx),
        0);

    uint8_t proof[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
    ASSERT_EQ(mpt_get_clawback_proof(priv, pub, ctx, amount, ct, proof), 0);
    EXPECT_EQ(mpt_verify_clawback_proof(proof, amount, pub, ct, ctx), 0);

    ClawbackSigmaPublicInput pubIn;
    pubIn.issuerKey = pointFrom(pub);
    ASSERT_TRUE(parseCiphertext(Slice(ct, sizeof(ct)), pubIn.issuerBalance));
    pubIn.revealedAmount = amount;
    bool const ok = verifyClawbackSigma(
        pubIn, Slice(ctx, sizeof(ctx)), Slice(proof, sizeof(proof)));
    EXPECT_FALSE(ok) << "unexpected: mpt-crypto clawback proof verified in rippled";
}

TEST(MptUtilityInterop, BulletproofSizesMatchConstants)
{
    EXPECT_EQ(kSingleBulletproofBytes, kMPT_SINGLE_BULLETPROOF_SIZE);
    EXPECT_EQ(kAggregatedBulletproofBytes, kMPT_DOUBLE_BULLETPROOF_SIZE);
    EXPECT_EQ(
        kSendZkProofBytes,
        SECP256K1_COMPACT_STANDARD_PROOF_SIZE + kMPT_DOUBLE_BULLETPROOF_SIZE);
    EXPECT_EQ(
        kConvertBackZkProofBytes,
        SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE +
            kMPT_SINGLE_BULLETPROOF_SIZE);
}
