//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2026 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
    SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
    OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
    CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <test/jtx.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace xrpl {

namespace cm = confidential_mpt;

class ConfidentialMPTFlow_test : public beast::unit_test::Suite
{
    struct EncryptionKey
    {
        cm::Scalar secret;
        cm::Point publicKey;
    };

    static cm::Scalar
    scalar(std::uint64_t value)
    {
        cm::Scalar result{};
        for (std::size_t i = 0; i < sizeof(value); ++i)
            result[31 - i] = static_cast<std::uint8_t>(value >> (8 * i));
        return result;
    }

    static EncryptionKey
    key(std::uint64_t value)
    {
        auto const secret = scalar(value);
        auto const publicKey = cm::pointMulBase(secret);
        if (!publicKey)
            Throw<std::runtime_error>("Unable to create Confidential MPT test key");
        return {secret, *publicKey};
    }

    template <std::size_t N>
    static std::string
    hex(std::array<std::uint8_t, N> const& value)
    {
        return strHex(Slice{value.data(), value.size()});
    }

    template <std::size_t N, std::size_t M>
    static std::string
    joinedHex(std::array<std::uint8_t, N> const& first, std::array<std::uint8_t, M> const& second)
    {
        Blob value;
        value.reserve(N + M);
        value.insert(value.end(), first.begin(), first.end());
        value.insert(value.end(), second.begin(), second.end());
        return strHex(value);
    }

    static Slice
    asSlice(uint256 const& value)
    {
        return Slice{value.data(), value.size()};
    }

    static uint256
    keyRegistrationContext(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint32_t sequence)
    {
        return sha512Half(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT),
            account.id(),
            issuanceID,
            sequence);
    }

    static uint256
    sendContext(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint32_t sequence,
        test::jtx::Account const& destination,
        std::uint32_t version)
    {
        return sha512Half(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
            account.id(),
            issuanceID,
            sequence,
            destination.id(),
            version);
    }

    static uint256
    convertBackContext(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint32_t sequence,
        std::uint32_t version)
    {
        return sha512Half(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
            account.id(),
            issuanceID,
            sequence,
            account.id(),
            version);
    }

    static uint256
    clawbackContext(
        test::jtx::Account const& issuer,
        MPTID const& issuanceID,
        std::uint32_t sequence,
        test::jtx::Account const& holder)
    {
        return sha512Half(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
            issuer.id(),
            issuanceID,
            sequence,
            holder.id(),
            std::uint32_t{0});
    }

    static void
    setConfidentialFee(json::Value& tx)
    {
        tx[jss::Fee] = "100";
    }

    static json::Value
    convertTx(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        EncryptionKey const& holderKey,
        EncryptionKey const& issuerKey,
        EncryptionKey const& auditorKey,
        cm::Scalar const& randomness,
        std::uint32_t sequence)
    {
        auto const holderAmount = cm::encryptAmount(holderKey.publicKey, amount, randomness);
        auto const issuerAmount = cm::encryptAmount(issuerKey.publicKey, amount, randomness);
        auto const auditorAmount = cm::encryptAmount(auditorKey.publicKey, amount, randomness);
        auto const context = keyRegistrationContext(account, issuanceID, sequence);
        auto const proof =
            cm::proveKeyRegistration(holderKey.secret, holderKey.publicKey, asSlice(context));
        if (!holderAmount || !issuerAmount || !auditorAmount || !proof)
            Throw<std::runtime_error>("Unable to create ConfidentialMPTConvert proof");

        json::Value tx;
        tx[jss::TransactionType] = jss::ConfidentialMPTConvert;
        tx[sfAccount] = account.human();
        tx[sfMPTokenIssuanceID] = to_string(issuanceID);
        tx[sfMPTAmount] = std::to_string(amount);
        tx[sfHolderEncryptionKey] = hex(holderKey.publicKey);
        tx[sfHolderEncryptedAmount] = hex(*holderAmount);
        tx[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        tx[sfAuditorEncryptedAmount] = hex(*auditorAmount);
        tx[sfBlindingFactor] = hex(randomness);
        tx[sfZKProof] = hex(*proof);
        setConfidentialFee(tx);
        return tx;
    }

    static json::Value
    mergeTx(test::jtx::Account const& account, MPTID const& issuanceID)
    {
        json::Value tx;
        tx[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
        tx[sfAccount] = account.human();
        tx[sfMPTokenIssuanceID] = to_string(issuanceID);
        setConfidentialFee(tx);
        return tx;
    }

    static json::Value
    convertTxWithoutKey(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        EncryptionKey const& holderKey,
        EncryptionKey const& issuerKey,
        EncryptionKey const& auditorKey,
        cm::Scalar const& randomness)
    {
        // Subsequent converts omit key registration (key already on MPToken).
        auto const holderAmount = cm::encryptAmount(holderKey.publicKey, amount, randomness);
        auto const issuerAmount = cm::encryptAmount(issuerKey.publicKey, amount, randomness);
        auto const auditorAmount = cm::encryptAmount(auditorKey.publicKey, amount, randomness);
        if (!holderAmount || !issuerAmount || !auditorAmount)
            Throw<std::runtime_error>("Unable to create subsequent Convert ciphertexts");

        json::Value tx;
        tx[jss::TransactionType] = jss::ConfidentialMPTConvert;
        tx[sfAccount] = account.human();
        tx[sfMPTokenIssuanceID] = to_string(issuanceID);
        tx[sfMPTAmount] = std::to_string(amount);
        tx[sfHolderEncryptedAmount] = hex(*holderAmount);
        tx[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        tx[sfAuditorEncryptedAmount] = hex(*auditorAmount);
        tx[sfBlindingFactor] = hex(randomness);
        setConfidentialFee(tx);
        return tx;
    }

    static json::Value
    convertTxIssuerOnly(
        test::jtx::Account const& account,
        MPTID const& issuanceID,
        std::uint64_t amount,
        EncryptionKey const& holderKey,
        EncryptionKey const& issuerKey,
        cm::Scalar const& randomness,
        std::uint32_t sequence)
    {
        auto const holderAmount = cm::encryptAmount(holderKey.publicKey, amount, randomness);
        auto const issuerAmount = cm::encryptAmount(issuerKey.publicKey, amount, randomness);
        auto const context = keyRegistrationContext(account, issuanceID, sequence);
        auto const proof =
            cm::proveKeyRegistration(holderKey.secret, holderKey.publicKey, asSlice(context));
        if (!holderAmount || !issuerAmount || !proof)
            Throw<std::runtime_error>("Unable to create issuer-only Convert proof");

        json::Value tx;
        tx[jss::TransactionType] = jss::ConfidentialMPTConvert;
        tx[sfAccount] = account.human();
        tx[sfMPTokenIssuanceID] = to_string(issuanceID);
        tx[sfMPTAmount] = std::to_string(amount);
        tx[sfHolderEncryptionKey] = hex(holderKey.publicKey);
        tx[sfHolderEncryptedAmount] = hex(*holderAmount);
        tx[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        tx[sfBlindingFactor] = hex(randomness);
        tx[sfZKProof] = hex(*proof);
        setConfidentialFee(tx);
        return tx;
    }

    void
    testIssuancePolicy()
    {
        testcase("issuance enable, immutability, and transfer fee policy");
        using namespace test::jtx;

        auto withoutDynamic =
            testableAmendments().set(featureConfidentialTransfer) - featureDynamicMPT;
        Env env(*this, withoutDynamic);
        Account const issuer{"policyIssuer"};
        Account const mutableIssuer{"mutablePolicyIssuer"};

        MPTTester enabled(env, issuer);
        enabled.create({.flags = tfMPTCanHoldConfidentialBalance});

        MPTTester mutableIssuance(env, mutableIssuer);
        mutableIssuance.create();
        auto const issuerKey = key(37);
        json::Value enable;
        enable[jss::TransactionType] = jss::MPTokenIssuanceSet;
        enable[sfAccount] = mutableIssuer.human();
        enable[sfMPTokenIssuanceID] = to_string(mutableIssuance.issuanceID());
        enable[sfIssuerEncryptionKey] = hex(issuerKey.publicKey);
        env(enable, Txflags(tfMPTSetCanHoldConfidentialBalance));

        json::Value auditorOnly;
        auditorOnly[jss::TransactionType] = jss::MPTokenIssuanceSet;
        auditorOnly[sfAccount] = mutableIssuer.human();
        auditorOnly[sfMPTokenIssuanceID] = to_string(mutableIssuance.issuanceID());
        auditorOnly[sfAuditorEncryptionKey] = hex(key(39).publicKey);
        env(auditorOnly, Ter(temMALFORMED));

        json::Value badFeeCreate;
        badFeeCreate[jss::TransactionType] = jss::MPTokenIssuanceCreate;
        badFeeCreate[sfAccount] = issuer.human();
        badFeeCreate[sfTransferFee] = 1;
        env(badFeeCreate,
            Txflags(tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance),
            Ter(temBAD_TRANSFER_FEE));

        auto withDynamic = withoutDynamic;
        withDynamic.set(featureDynamicMPT);
        Env immutableEnv(*this, withDynamic);
        Account const immutableIssuer{"immutablePolicyIssuer"};
        Account const feeIssuer{"feePolicyIssuer"};
        immutableEnv.fund(XRP(10'000), immutableIssuer);
        auto const immutableID = makeMptID(immutableEnv.seq(immutableIssuer), immutableIssuer);

        json::Value createImmutable;
        createImmutable[jss::TransactionType] = jss::MPTokenIssuanceCreate;
        createImmutable[sfAccount] = immutableIssuer.human();
        createImmutable[sfImmutableFlags] = tifMPTCanHoldConfidentialBalance;
        immutableEnv(createImmutable);

        json::Value lockedEnable;
        lockedEnable[jss::TransactionType] = jss::MPTokenIssuanceSet;
        lockedEnable[sfAccount] = immutableIssuer.human();
        lockedEnable[sfMPTokenIssuanceID] = to_string(immutableID);
        immutableEnv(
            lockedEnable, Txflags(tfMPTSetCanHoldConfidentialBalance), Ter(tecNO_PERMISSION));

        MPTTester feeIssuance(immutableEnv, feeIssuer);
        feeIssuance.create(
            {.flags = tfMPTCanHoldConfidentialBalance, .mutableFlags = tmfMPTCanMutateTransferFee});
        json::Value setFee;
        setFee[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setFee[sfAccount] = feeIssuer.human();
        setFee[sfMPTokenIssuanceID] = to_string(feeIssuance.issuanceID());
        setFee[sfTransferFee] = 1;
        immutableEnv(setFee, Ter(tecNO_PERMISSION));
    }

    void
    testFlow()
    {
        testcase("convert, merge, send, convert back, and clawback");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const bob{"bob"};

        MPTTester mpt(env, issuer, {.holders = {alice, bob}});
        mpt.create(
            {.maxAmt = 1'000,
             .authorize = MPTCreate::allHolders,
             .pay = {{{alice}, 100}},
             .flags = tfMPTCanTransfer | tfMPTCanClawback | tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();

        auto const issuerEncryption = key(17);
        auto const auditorEncryption = key(19);
        auto const aliceEncryption = key(11);
        auto const bobEncryption = key(13);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
        env(setKeys);

        env(convertTx(
            alice,
            issuanceID,
            100,
            aliceEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(7),
            env.seq(alice)));
        env(mergeTx(alice, issuanceID));
        env(convertTx(
            bob,
            issuanceID,
            0,
            bobEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(9),
            env.seq(bob)));

        auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(aliceMpt))
            return;
        auto const aliceSpending = cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(aliceSpending))
            return;

        std::uint64_t constexpr amount = 30;
        std::uint64_t constexpr aliceBalance = 100;
        auto const sendRandomness = scalar(19);
        auto const balanceBlinding = scalar(23);
        auto const remainderBlinding = scalar(4);
        auto const senderAmount =
            cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
        auto const destinationAmount =
            cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
        auto const issuerAmount =
            cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
        auto const auditorAmount =
            cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
        auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
        auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
        auto const remainderCommitment =
            cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
        if (!BEAST_EXPECT(
                senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                amountCommitment && balanceCommitment && remainderCommitment))
            return;

        json::Value send;
        send[jss::TransactionType] = jss::ConfidentialMPTSend;
        send[sfAccount] = alice.human();
        send[sfDestination] = bob.human();
        send[sfMPTokenIssuanceID] = to_string(issuanceID);
        send[sfSenderEncryptedAmount] = hex(*senderAmount);
        send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
        send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
        send[sfAmountCommitment] = hex(*amountCommitment);
        send[sfBalanceCommitment] = hex(*balanceCommitment);
        setConfidentialFee(send);

        auto const aliceVersion = (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
        auto sendCtx = sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
        cm::SendPublicInput sendInput{
            .recipientKeys =
                {aliceEncryption.publicKey,
                 bobEncryption.publicKey,
                 issuerEncryption.publicKey,
                 auditorEncryption.publicKey},
            .senderKey = aliceEncryption.publicKey,
            .c1 = cm::ciphertextC1(*senderAmount),
            .c2 =
                {cm::ciphertextC2(*senderAmount),
                 cm::ciphertextC2(*destinationAmount),
                 cm::ciphertextC2(*issuerAmount),
                 cm::ciphertextC2(*auditorAmount)},
            .amountCommitment = *amountCommitment,
            .balanceCommitment = *balanceCommitment,
            .balanceC1 = cm::ciphertextC1(*aliceSpending),
            .balanceC2 = cm::ciphertextC2(*aliceSpending)};
        cm::SendWitness const sendWitness{
            .m = amount,
            .r = sendRandomness,
            .b = aliceBalance,
            .rho = balanceBlinding,
            .sk = aliceEncryption.secret};
        auto sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
        auto range = cm::proveAggregatedBulletproof(
            *amountCommitment,
            *remainderCommitment,
            amount,
            sendRandomness,
            aliceBalance - amount,
            remainderBlinding,
            asSlice(sendCtx));
        if (!BEAST_EXPECT(sigma && range))
            return;
        send[sfZKProof] = joinedHex(*sigma, *range);

        env(fset(bob, asfDepositAuth));
        env(send, Ter(tecNO_PERMISSION));
        env(deposit::auth(bob, alice));

        sendCtx = sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
        sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
        range = cm::proveAggregatedBulletproof(
            *amountCommitment,
            *remainderCommitment,
            amount,
            sendRandomness,
            aliceBalance - amount,
            remainderBlinding,
            asSlice(sendCtx));
        if (!BEAST_EXPECT(sigma && range))
            return;
        send[sfZKProof] = joinedHex(*sigma, *range);
        env(send);

        env(mergeTx(bob, issuanceID));
        auto const bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
        if (!BEAST_EXPECT(bobMpt))
            return;
        auto const bobSpending = cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(bobSpending))
            return;

        auto const withdrawRandomness = scalar(29);
        auto const withdrawBlinding = scalar(31);
        auto const holderWithdrawal =
            cm::encryptAmount(bobEncryption.publicKey, amount, withdrawRandomness);
        auto const issuerWithdrawal =
            cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
        auto const auditorWithdrawal =
            cm::encryptAmount(auditorEncryption.publicKey, amount, withdrawRandomness);
        auto const withdrawBalanceCommitment = cm::pedersenCommit(amount, withdrawBlinding);
        auto const withdrawRemainderCommitment = cm::pedersenCommit(0, withdrawBlinding);
        if (!BEAST_EXPECT(
                holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                withdrawBalanceCommitment && withdrawRemainderCommitment))
            return;

        auto const bobVersion = (*bobMpt)[~sfConfidentialBalanceVersion].value_or(0);
        auto const withdrawCtx = convertBackContext(bob, issuanceID, env.seq(bob), bobVersion);
        cm::ConvertBackPublicInput const withdrawInput{
            .holderKey = bobEncryption.publicKey,
            .balanceC1 = cm::ciphertextC1(*bobSpending),
            .balanceC2 = cm::ciphertextC2(*bobSpending),
            .balanceCommitment = *withdrawBalanceCommitment};
        cm::ConvertBackWitness const withdrawWitness{
            .b = amount, .rho = withdrawBlinding, .sk = bobEncryption.secret};
        auto const withdrawSigma =
            cm::proveConvertBackSigma(withdrawInput, withdrawWitness, asSlice(withdrawCtx));
        auto const withdrawRange = cm::proveSingleBulletproof(
            *withdrawRemainderCommitment, 0, withdrawBlinding, asSlice(withdrawCtx));
        if (!BEAST_EXPECT(withdrawSigma && withdrawRange))
            return;

        json::Value convertBack;
        convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        convertBack[sfAccount] = bob.human();
        convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
        convertBack[sfMPTAmount] = std::to_string(amount);
        convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
        convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
        convertBack[sfAuditorEncryptedAmount] = hex(*auditorWithdrawal);
        convertBack[sfBlindingFactor] = hex(withdrawRandomness);
        convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
        convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
        setConfidentialFee(convertBack);
        env(convertBack);

        auto const aliceAfterSend = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(aliceAfterSend))
            return;
        auto const aliceIssuerBalance =
            cm::parseCiphertext((*aliceAfterSend)[sfIssuerEncryptedBalance]);
        if (!BEAST_EXPECT(aliceIssuerBalance))
            return;

        cm::ClawbackPublicInput const clawInput{
            .issuerKey = issuerEncryption.publicKey,
            .c1 = cm::ciphertextC1(*aliceIssuerBalance),
            .c2 = cm::ciphertextC2(*aliceIssuerBalance),
            .m = aliceBalance - amount};
        auto const clawCtx = clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
        auto const clawProof =
            cm::proveClawback(clawInput, issuerEncryption.secret, asSlice(clawCtx));
        if (!BEAST_EXPECT(clawProof))
            return;

        json::Value clawback;
        clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
        clawback[sfAccount] = issuer.human();
        clawback[sfHolder] = alice.human();
        clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
        clawback[sfMPTAmount] = std::to_string(aliceBalance - amount);
        clawback[sfZKProof] = hex(*clawProof);
        setConfidentialFee(clawback);
        env(clawback);

        auto const issuance = env.le(keylet::mptIssuance(issuanceID));
        auto const finalBobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
        auto const finalAliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(issuance && finalBobMpt && finalAliceMpt))
            return;
        BEAST_EXPECT((*issuance)[sfOutstandingAmount] == amount);
        BEAST_EXPECT((*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 0);
        BEAST_EXPECT((*finalBobMpt)[sfMPTAmount] == amount);
        auto const auditorZero = confidentialMPTEncryptedZero(
            auditorEncryption.publicKey, alice.id(), issuer.id(), issuanceID);
        if (!BEAST_EXPECT(auditorZero))
            return;
        auto const finalAuditorBalance =
            cm::parseCiphertext((*finalAliceMpt)[sfAuditorEncryptedBalance]);
        BEAST_EXPECT(finalAuditorBalance && *finalAuditorBalance == *auditorZero);

        json::Value removeAlice;
        removeAlice[jss::TransactionType] = jss::MPTokenAuthorize;
        removeAlice[sfAccount] = alice.human();
        removeAlice[sfMPTokenIssuanceID] = to_string(issuanceID);
        env(removeAlice, Txflags(tfMPTUnauthorize), Ter(tecHAS_OBLIGATIONS));
    }

    void
    testNegativePaths()
    {
        testcase("negative paths: issuer forbidden, dest=issuer, non-issuer clawback");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"negIssuer"};
        Account const alice{"negAlice"};
        Account const bob{"negBob"};

        MPTTester mpt(env, issuer, {.holders = {alice, bob}});
        mpt.create(
            {.maxAmt = 1'000,
             .authorize = MPTCreate::allHolders,
             .pay = {{{alice}, 50}},
             .flags = tfMPTCanTransfer | tfMPTCanClawback | tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();

        auto const issuerEncryption = key(41);
        auto const auditorEncryption = key(43);
        auto const aliceEncryption = key(47);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
        env(setKeys);

        // Issuer cannot Convert (dedicated-account model).
        env(convertTx(
                issuer,
                issuanceID,
                0,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(issuer)),
            Ter(temMALFORMED));

        // Issuer cannot MergeInbox.
        env(mergeTx(issuer, issuanceID), Ter(temMALFORMED));

        // Issuer cannot ConvertBack (xls-0096 ConvertBack data verification).
        {
            auto const r = scalar(8);
            auto const holderCt = cm::encryptAmount(aliceEncryption.publicKey, 1, r);
            auto const issuerCt = cm::encryptAmount(issuerEncryption.publicKey, 1, r);
            auto const auditorCt = cm::encryptAmount(auditorEncryption.publicKey, 1, r);
            auto const commitment = cm::pedersenCommit(0, scalar(1));
            if (!BEAST_EXPECT(holderCt && issuerCt && auditorCt && commitment))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = issuer.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = "1";
            convertBack[sfHolderEncryptedAmount] = hex(*holderCt);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerCt);
            convertBack[sfAuditorEncryptedAmount] = hex(*auditorCt);
            convertBack[sfBlindingFactor] = hex(r);
            convertBack[sfBalanceCommitment] = hex(*commitment);
            convertBack[sfZKProof] = hex(std::array<std::uint8_t, 816>{});
            setConfidentialFee(convertBack);
            env(convertBack, Ter(temMALFORMED));
        }

        env(convertTx(
            alice,
            issuanceID,
            50,
            aliceEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(5),
            env.seq(alice)));
        env(mergeTx(alice, issuanceID));

        auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(aliceMpt))
            return;
        auto const aliceSpending = cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(aliceSpending))
            return;

        std::uint64_t constexpr amount = 10;
        std::uint64_t constexpr aliceBalance = 50;
        auto const sendRandomness = scalar(11);
        auto const balanceBlinding = scalar(13);
        auto const remainderBlinding = scalar(2);
        auto const senderAmount =
            cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
        auto const destinationAmount =
            cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
        auto const issuerAmount =
            cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
        auto const auditorAmount =
            cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
        auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
        auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
        auto const remainderCommitment =
            cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
        if (!BEAST_EXPECT(
                senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                amountCommitment && balanceCommitment && remainderCommitment))
            return;

        // Destination must not be the issuance issuer.
        {
            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = issuer.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            setConfidentialFee(send);

            auto const aliceVersion = (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const ctx = sendContext(alice, issuanceID, env.seq(alice), issuer, aliceVersion);
            cm::SendPublicInput sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     aliceEncryption.publicKey,
                     issuerEncryption.publicKey,
                     auditorEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount),
                     cm::ciphertextC2(*auditorAmount)},
                .amountCommitment = *amountCommitment,
                .balanceCommitment = *balanceCommitment,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending)};
            cm::SendWitness const sendWitness{
                .m = amount,
                .r = sendRandomness,
                .b = aliceBalance,
                .rho = balanceBlinding,
                .sk = aliceEncryption.secret};
            auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(ctx));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(ctx));
            if (!BEAST_EXPECT(sigma && range))
                return;
            send[sfZKProof] = joinedHex(*sigma, *range);
            env(send, Ter(tecNO_PERMISSION));
        }

        // Non-issuer cannot Clawback.
        {
            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = alice.human();
            clawback[sfHolder] = bob.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(temMALFORMED));
        }

        // ConvertBack with amount exceeding COA.
        {
            auto const withdrawRandomness = scalar(17);
            auto const withdrawBlinding = scalar(19);
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, 51, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, 51, withdrawRandomness);
            auto const auditorWithdrawal =
                cm::encryptAmount(auditorEncryption.publicKey, 51, withdrawRandomness);
            auto const withdrawBalanceCommitment = cm::pedersenCommit(50, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(static_cast<std::uint64_t>(-1), withdrawBlinding);
            // Use a syntactically sized but intentionally insufficient-COA amount.
            if (!BEAST_EXPECT(holderWithdrawal && issuerWithdrawal && auditorWithdrawal))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = "51";
            convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
            convertBack[sfAuditorEncryptedAmount] = hex(*auditorWithdrawal);
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            // 128-byte sigma + 688-byte range placeholder; preclaim should fail on COA.
            convertBack[sfZKProof] = hex(std::array<std::uint8_t, 816>{});
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecINSUFFICIENT_FUNDS));
            (void)withdrawRemainderCommitment;
        }
    }

    void
    testFeesAndPolicyFailures()
    {
        testcase("10x base fee, EncZero pin, clawback flag, destroy with COA");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"feeIssuer"};
        Account const alice{"feeAlice"};
        Account const bob{"feeBob"};

        // --- 10x fee (XLS-0096 §14.2) ---
        {
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 1'000,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();

            auto checkTenX = [&](json::Value jv) {
                setConfidentialFee(jv);
                auto const jtx = env.jt(jv);
                if (!BEAST_EXPECT(jtx.stx))
                    return;
                auto const base = Transactor::calculateBaseFee(*env.current(), *jtx.stx);
                auto const typed = [&]() -> XRPAmount {
                    switch (jtx.stx->getTxnType())
                    {
                        case ttCONFIDENTIAL_MPT_CONVERT:
                            return ConfidentialMPTConvert::calculateBaseFee(
                                *env.current(), *jtx.stx);
                        case ttCONFIDENTIAL_MPT_MERGE_INBOX:
                            return ConfidentialMPTMergeInbox::calculateBaseFee(
                                *env.current(), *jtx.stx);
                        case ttCONFIDENTIAL_MPT_CONVERT_BACK:
                            return ConfidentialMPTConvertBack::calculateBaseFee(
                                *env.current(), *jtx.stx);
                        case ttCONFIDENTIAL_MPT_SEND:
                            return ConfidentialMPTSend::calculateBaseFee(
                                *env.current(), *jtx.stx);
                        case ttCONFIDENTIAL_MPT_CLAWBACK:
                            return ConfidentialMPTClawback::calculateBaseFee(
                                *env.current(), *jtx.stx);
                        default:
                            return XRPAmount{0};
                    }
                }();
                BEAST_EXPECT(typed == base * 10);
            };

            checkTenX(mergeTx(alice, issuanceID));

            json::Value convert;
            convert[jss::TransactionType] = jss::ConfidentialMPTConvert;
            convert[sfAccount] = alice.human();
            convert[sfMPTokenIssuanceID] = to_string(issuanceID);
            convert[sfMPTAmount] = "1";
            convert[sfHolderEncryptionKey] = std::string(66, '0');
            convert[sfHolderEncryptedAmount] = std::string(132, '0');
            convert[sfIssuerEncryptedAmount] = std::string(132, '0');
            convert[sfBlindingFactor] = std::string(64, '0');
            convert[sfZKProof] = std::string(128, '0');
            checkTenX(convert);

            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = std::string(132, '0');
            send[sfDestinationEncryptedAmount] = std::string(132, '0');
            send[sfIssuerEncryptedAmount] = std::string(132, '0');
            send[sfAmountCommitment] = std::string(66, '0');
            send[sfBalanceCommitment] = std::string(66, '0');
            send[sfZKProof] = std::string(946 * 2, '0');
            checkTenX(send);

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = "1";
            convertBack[sfHolderEncryptedAmount] = std::string(132, '0');
            convertBack[sfIssuerEncryptedAmount] = std::string(132, '0');
            convertBack[sfBlindingFactor] = std::string(64, '0');
            convertBack[sfBalanceCommitment] = std::string(66, '0');
            convertBack[sfZKProof] = std::string(816 * 2, '0');
            checkTenX(convertBack);

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = std::string(128, '0');
            checkTenX(clawback);
        }

        // --- EncZero pin: helper ciphertext is deterministic ---
        {
            auto const pk = key(99).publicKey;
            AccountID const acct = alice.id();
            AccountID const iss = issuer.id();
            MPTID const id = makeMptID(1, issuer);
            auto const a = confidentialMPTEncryptedZero(pk, acct, iss, id);
            auto const b = confidentialMPTEncryptedZero(pk, acct, iss, id);
            BEAST_EXPECT(a && b && *a == *b);
            auto const c = confidentialMPTEncryptedZero(pk, bob.id(), iss, id);
            BEAST_EXPECT(c && a && *c != *a);
        }

        // --- Clawback requires lsfMPTCanClawback ---
        {
            Account const noClawIssuer{"noClawIssuer"};
            Account const noClawAlice{"noClawAlice"};
            MPTTester mpt(env, noClawIssuer, {.holders = {noClawAlice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{noClawAlice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(71);
            auto const auditorEncryption = key(73);
            auto const aliceEncryption = key(75);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = noClawIssuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                noClawAlice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(7),
                env.seq(noClawAlice)));
            env(mergeTx(noClawAlice, issuanceID));

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = noClawIssuer.human();
            clawback[sfHolder] = noClawAlice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "20";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(tecNO_PERMISSION));

            mpt.destroy({.err = tecHAS_OBLIGATIONS});
        }

        // --- Lock blocks MergeInbox (XLS-0096; terFROZEN absent -> tecLOCKED) ---
        {
            Account const lockIssuer{"lockIssuer"};
            Account const lockAlice{"lockAlice"};
            MPTTester mpt(env, lockIssuer, {.holders = {lockAlice}});
            mpt.create(
                {.maxAmt = 200,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{lockAlice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanLock | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(81);
            auto const auditorEncryption = key(83);
            auto const aliceEncryption = key(85);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = lockIssuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                lockAlice,
                issuanceID,
                40,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(lockAlice)));
            env(mergeTx(lockAlice, issuanceID));

            // Global issuance lock via MPTokenIssuanceSet.
            json::Value lockTx;
            lockTx[jss::TransactionType] = jss::MPTokenIssuanceSet;
            lockTx[sfAccount] = lockIssuer.human();
            lockTx[sfMPTokenIssuanceID] = to_string(issuanceID);
            env(lockTx, Txflags(tfMPTLock));

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            BEAST_EXPECT(issuance && issuance->isFlag(lsfMPTLocked));

            env(mergeTx(lockAlice, issuanceID), Ter(tecLOCKED));

            env(lockTx, Txflags(tfMPTUnlock));

            json::Value holderLock = lockTx;
            holderLock[sfHolder] = lockAlice.human();
            env(holderLock, Txflags(tfMPTLock));

            auto const holder = env.le(keylet::mptoken(issuanceID, lockAlice.id()));
            BEAST_EXPECT(holder && holder->isFlag(lsfMPTLocked));
            env(mergeTx(lockAlice, issuanceID), Ter(tecLOCKED));
        }

        // --- Lock blocks ConfidentialMPTSend / ConvertBack after ledger close ---
        {
            Account const lockIssuer{"lockSendIssuer"};
            Account const lockAlice{"lockSendAlice"};
            Account const lockBob{"lockSendBob"};
            MPTTester mpt(env, lockIssuer, {.holders = {lockAlice, lockBob}});
            mpt.create(
                {.maxAmt = 200,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{lockAlice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanLock | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(101);
            auto const auditorEncryption = key(103);
            auto const aliceEncryption = key(105);
            auto const bobEncryption = key(107);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = lockIssuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                lockAlice,
                issuanceID,
                40,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(5),
                env.seq(lockAlice)));
            env(mergeTx(lockAlice, issuanceID));
            env(convertTx(
                lockBob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(11),
                env.seq(lockBob)));

            // Re-deserialize from SHAMap to exercise canonical SoeDefault fields.
            env.close();

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, lockAlice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 10;
            std::uint64_t constexpr aliceBalance = 40;
            auto const sendRandomness = scalar(13);
            auto const balanceBlinding = scalar(17);
            auto const remainderBlinding = scalar(19);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = lockAlice.human();
            send[sfDestination] = lockBob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            setConfidentialFee(send);

            auto const aliceVersion = (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const sendCtx =
                sendContext(lockAlice, issuanceID, env.seq(lockAlice), lockBob, aliceVersion);
            cm::SendPublicInput sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     bobEncryption.publicKey,
                     issuerEncryption.publicKey,
                     auditorEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount),
                     cm::ciphertextC2(*auditorAmount)},
                .amountCommitment = *amountCommitment,
                .balanceCommitment = *balanceCommitment,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending)};
            cm::SendWitness const sendWitness{
                .m = amount,
                .r = sendRandomness,
                .b = aliceBalance,
                .rho = balanceBlinding,
                .sk = aliceEncryption.secret};
            auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(sendCtx));
            if (!BEAST_EXPECT(sigma && range))
                return;
            send[sfZKProof] = joinedHex(*sigma, *range);

            // Construct valid ConvertBack for alice (non-zero; preflight rejects 0).
            auto const withdrawRandomness = scalar(23);
            auto const withdrawBlinding = scalar(29);
            std::uint64_t constexpr withdrawAmt = 10;
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, withdrawAmt, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, withdrawAmt, withdrawRandomness);
            auto const auditorWithdrawal =
                cm::encryptAmount(auditorEncryption.publicKey, withdrawAmt, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(aliceBalance, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(aliceBalance - withdrawAmt, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
                return;
            auto const withdrawCtx =
                convertBackContext(lockAlice, issuanceID, env.seq(lockAlice), aliceVersion);
            cm::ConvertBackPublicInput const withdrawInput{
                .holderKey = aliceEncryption.publicKey,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending),
                .balanceCommitment = *withdrawBalanceCommitment};
            cm::ConvertBackWitness const withdrawWitness{
                .b = aliceBalance, .rho = withdrawBlinding, .sk = aliceEncryption.secret};
            auto const withdrawSigma =
                cm::proveConvertBackSigma(withdrawInput, withdrawWitness, asSlice(withdrawCtx));
            auto const withdrawRange = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment,
                aliceBalance - withdrawAmt,
                withdrawBlinding,
                asSlice(withdrawCtx));
            if (!BEAST_EXPECT(withdrawSigma && withdrawRange))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = lockAlice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = std::to_string(withdrawAmt);
            convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
            convertBack[sfAuditorEncryptedAmount] = hex(*auditorWithdrawal);
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);

            json::Value lockTx;
            lockTx[jss::TransactionType] = jss::MPTokenIssuanceSet;
            lockTx[sfAccount] = lockIssuer.human();
            lockTx[sfMPTokenIssuanceID] = to_string(issuanceID);
            env(lockTx, Txflags(tfMPTLock));

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            BEAST_EXPECT(issuance && issuance->isFlag(lsfMPTLocked));

            // ConvertBack before Send so fee/seq from tecLOCKED does not
            // invalidate the ConvertBack proof sequence binding.
            env(convertBack, Ter(tecLOCKED));
            env(send, Ter(tecLOCKED));
        }

        // --- Dedicated vault account may convert (issuer account may not) ---
        {
            Account const vaultIssuer{"vaultIssuer"};
            Account const vault{"vault"};
            Account const vaultBob{"vaultBob"};
            MPTTester mpt(env, vaultIssuer, {.holders = {vault, vaultBob}});
            mpt.create(
                {.maxAmt = 500,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{vault}, 80}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(91);
            auto const auditorEncryption = key(93);
            auto const vaultEncryption = key(95);
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = vaultIssuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            // Issuer still forbidden.
            env(convertTx(
                    vaultIssuer,
                    issuanceID,
                    1,
                    vaultEncryption,
                    issuerEncryption,
                    auditorEncryption,
                    scalar(2),
                    env.seq(vaultIssuer)),
                Ter(temMALFORMED));

            // Dedicated vault converts like any holder.
            env(convertTx(
                vault,
                issuanceID,
                80,
                vaultEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(11),
                env.seq(vault)));
            env(mergeTx(vault, issuanceID));

            auto const vaultMpt = env.le(keylet::mptoken(issuanceID, vault.id()));
            if (!BEAST_EXPECT(vaultMpt))
                return;
            auto const version = (*vaultMpt)[sfConfidentialBalanceVersion];
            auto const expectedInbox = confidentialMPTEncryptedZero(
                vaultEncryption.publicKey, vault.id(), vaultIssuer.id(), issuanceID);
            if (!BEAST_EXPECT(expectedInbox))
                return;

            // An empty inbox is still mergeable: it resets to EncZero and
            // advances the proof version without changing supply.
            env(mergeTx(vault, issuanceID));
            auto const afterNoOp = env.le(keylet::mptoken(issuanceID, vault.id()));
            if (!BEAST_EXPECT(afterNoOp))
                return;
            BEAST_EXPECT((*afterNoOp)[sfConfidentialBalanceVersion] == version + 1);
            auto const inbox =
                cm::parseCiphertext((*afterNoOp)[sfConfidentialBalanceInbox]);
            BEAST_EXPECT(inbox && *inbox == *expectedInbox);

            auto const iss = env.le(keylet::mptIssuance(issuanceID));
            BEAST_EXPECT(iss && (*iss)[~sfConfidentialOutstandingAmount].value_or(0) == 80);
        }
    }


    void
    testAmendmentDisabled()
    {
        testcase("confidential transactions and issuance changes disabled");
        using namespace test::jtx;

        Env env(*this, testableAmendments() - featureConfidentialTransfer);
        Account const issuer{"disIssuer"};
        Account const alice{"disAlice"};
        env.fund(XRP(10'000), issuer, alice);
        env.close();

        auto const id = makeMptID(env.seq(issuer), issuer);
        env(convertTx(
                alice,
                id,
                1,
                key(3),
                key(5),
                key(7),
                scalar(9),
                env.seq(alice)),
            Ter(temDISABLED));
        env(mergeTx(alice, id), Ter(temDISABLED));

        json::Value create;
        create[jss::TransactionType] = jss::MPTokenIssuanceCreate;
        create[sfAccount] = issuer.human();
        env(
            create,
            Txflags(tfMPTCanHoldConfidentialBalance),
            Ter(temDISABLED));

        json::Value set;
        set[jss::TransactionType] = jss::MPTokenIssuanceSet;
        set[sfAccount] = issuer.human();
        set[sfMPTokenIssuanceID] = to_string(id);
        set[sfIssuerEncryptionKey] = hex(key(11).publicKey);
        env(set, Txflags(tfMPTSetCanHoldConfidentialBalance), Ter(temDISABLED));
    }

    void
    testConvertDuplicateKey()
    {
        testcase("Convert rejects re-registering HolderEncryptionKey");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"dupIssuer"};
        Account const alice{"dupAlice"};

        MPTTester mpt(env, issuer, {.holders = {alice}});
        mpt.create(
            {.maxAmt = 200,
             .authorize = MPTCreate::allHolders,
             .pay = {{{alice}, 50}},
             .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();
        auto const issuerEncryption = key(21);
        auto const auditorEncryption = key(23);
        auto const aliceEncryption = key(25);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
        env(setKeys);

        env(convertTx(
            alice,
            issuanceID,
            20,
            aliceEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(2),
            env.seq(alice)));

        // Re-submitting a holder key after registration is tecDUPLICATE.
        env(convertTx(
                alice,
                issuanceID,
                10,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(4),
                env.seq(alice)),
            Ter(tecDUPLICATE));

        // Subsequent convert without key registration succeeds.
        env(convertTxWithoutKey(
            alice,
            issuanceID,
            10,
            aliceEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(6)));
    }

    void
    testPermissionGates()
    {
        testcase("xls-0096 permission gates: flag, auth, dest init, keys, clawback");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);

        // Convert on a public-only issuance (no lsfMPTCanHoldConfidentialBalance).
        {
            Account const issuer{"pubIssuer"};
            Account const alice{"pubAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer});
            env(convertTx(
                    alice,
                    mpt.issuanceID(),
                    1,
                    key(3),
                    key(5),
                    key(7),
                    scalar(9),
                    env.seq(alice)),
                Ter(tecNO_PERMISSION));
        }

        // ConvertBack / Clawback against public MPToken (no confidential init).
        {
            Account const issuer{"cbIssuer"};
            Account const alice{"cbAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const aliceKey = key(41);
            auto const r = scalar(3);
            auto const holderAmount = cm::encryptAmount(aliceKey.publicKey, 1, r);
            auto const issuerAmount = cm::encryptAmount(aliceKey.publicKey, 1, r);
            auto const commitment = cm::pedersenCommit(0, scalar(5));
            if (!BEAST_EXPECT(holderAmount && issuerAmount && commitment))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = "1";
            convertBack[sfHolderEncryptedAmount] = hex(*holderAmount);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            convertBack[sfBlindingFactor] = hex(r);
            convertBack[sfBalanceCommitment] = hex(*commitment);
            convertBack[sfZKProof] = hex(std::array<std::uint8_t, 816>{});
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecNO_PERMISSION));

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(tecNO_PERMISSION));
        }

        // MergeInbox requires lsfMPTAuthorized when lsfMPTRequireAuth is set.
        {
            Account const issuer{"authIssuer"};
            Account const alice{"authAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .flags = tfMPTCanTransfer | tfMPTRequireAuth | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(51);
            auto const aliceEncryption = key(53);
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            // Convert does not gate lsfMPTRequireAuth; MergeInbox does.
            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                0,
                aliceEncryption,
                issuerEncryption,
                scalar(2),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID), Ter(tecNO_AUTH));
        }

        // Send destination must already have confidential state.
        {
            Account const issuer{"dstIssuer"};
            Account const alice{"dstAlice"};
            Account const bob{"dstBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 50}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(61);
            auto const auditorEncryption = key(63);
            auto const aliceEncryption = key(65);
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                alice,
                issuanceID,
                50,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(4),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 10;
            std::uint64_t constexpr aliceBalance = 50;
            auto const sendRandomness = scalar(11);
            auto const balanceBlinding = scalar(13);
            auto const remainderBlinding = scalar(2);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            setConfidentialFee(send);

            auto const aliceVersion = (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const ctx = sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
            cm::SendPublicInput sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     aliceEncryption.publicKey,
                     issuerEncryption.publicKey,
                     auditorEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount),
                     cm::ciphertextC2(*auditorAmount)},
                .amountCommitment = *amountCommitment,
                .balanceCommitment = *balanceCommitment,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending)};
            cm::SendWitness const sendWitness{
                .m = amount,
                .r = sendRandomness,
                .b = aliceBalance,
                .rho = balanceBlinding,
                .sk = aliceEncryption.secret};
            auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(ctx));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(ctx));
            if (!BEAST_EXPECT(sigma && range))
                return;
            send[sfZKProof] = joinedHex(*sigma, *range);
            env(send, Ter(tecNO_PERMISSION));
        }

        // Keys cannot be uploaded once COA is present; auditor-only is temMALFORMED.
        {
            Account const issuer{"coaIssuer"};
            Account const alice{"coaAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(71);
            auto const aliceEncryption = key(73);
            json::Value setIssuer;
            setIssuer[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setIssuer[sfAccount] = issuer.human();
            setIssuer[sfMPTokenIssuanceID] = to_string(issuanceID);
            setIssuer[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setIssuer);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                10,
                aliceEncryption,
                issuerEncryption,
                scalar(6),
                env.seq(alice)));

            json::Value auditorOnly;
            auditorOnly[jss::TransactionType] = jss::MPTokenIssuanceSet;
            auditorOnly[sfAccount] = issuer.human();
            auditorOnly[sfMPTokenIssuanceID] = to_string(issuanceID);
            auditorOnly[sfAuditorEncryptionKey] = hex(key(75).publicKey);
            env(auditorOnly, Ter(temMALFORMED));

            json::Value bothKeys;
            bothKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            bothKeys[sfAccount] = issuer.human();
            bothKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            bothKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            bothKeys[sfAuditorEncryptionKey] = hex(key(75).publicKey);
            env(bothKeys, Ter(tecNO_PERMISSION));
        }
    }

    void
    testProtocolFailures()
    {
        testcase("xls-0096 protocol failures: issuer send, no-transfer, no-dst, funds, proofs");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);

        // Convert amount exceeding public MPT balance → tecINSUFFICIENT_FUNDS.
        {
            Account const issuer{"fundsIssuer"};
            Account const alice{"fundsAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 5}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(81);
            auto const auditorEncryption = key(83);
            auto const aliceEncryption = key(85);
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);
            env(convertTx(
                    alice,
                    issuanceID,
                    6,
                    aliceEncryption,
                    issuerEncryption,
                    auditorEncryption,
                    scalar(1),
                    env.seq(alice)),
                Ter(tecINSUFFICIENT_FUNDS));
        }

        // Clawback against a holder account that does not exist → tecNO_TARGET.
        {
            Account const issuer{"clawIssuer"};
            Account const alice{"clawAlice"};
            Account const ghost{"clawGhost"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(key(91).publicKey);
            env(setKeys);
            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = ghost.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(tecNO_TARGET));
        }

        // Issuance without tfMPTCanTransfer rejects ConfidentialMPTSend with tecNO_AUTH.
        // Issuer-as-sender is temMALFORMED. Missing destination account is tecNO_TARGET.
        // Garbage ZKProof after valid setup is tecBAD_PROOF.
        {
            Account const issuer{"protoIssuer"};
            Account const alice{"protoAlice"};
            Account const bob{"protoBob"};
            Account const carol{"protoCarol"};  // never funded
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice, bob}, 40}},
                 .flags = tfMPTCanHoldConfidentialBalance});  // no CanTransfer
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(101);
            auto const auditorEncryption = key(103);
            auto const aliceEncryption = key(105);
            auto const bobEncryption = key(107);
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                alice,
                issuanceID,
                40,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTx(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(5),
                env.seq(bob)));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 5;
            std::uint64_t constexpr aliceBalance = 40;
            auto const sendRandomness = scalar(17);
            auto const balanceBlinding = scalar(19);
            auto const remainderBlinding = scalar(2);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto buildSend = [&](Account const& dest, std::uint32_t seq) {
                json::Value send;
                send[jss::TransactionType] = jss::ConfidentialMPTSend;
                send[sfAccount] = alice.human();
                send[sfDestination] = dest.human();
                send[sfMPTokenIssuanceID] = to_string(issuanceID);
                send[sfSenderEncryptedAmount] = hex(*senderAmount);
                send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
                send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
                send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
                send[sfAmountCommitment] = hex(*amountCommitment);
                send[sfBalanceCommitment] = hex(*balanceCommitment);
                setConfidentialFee(send);

                auto const aliceVersion =
                    (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
                auto const ctx = sendContext(alice, issuanceID, seq, dest, aliceVersion);
                cm::SendPublicInput sendInput{
                    .recipientKeys =
                        {aliceEncryption.publicKey,
                         bobEncryption.publicKey,
                         issuerEncryption.publicKey,
                         auditorEncryption.publicKey},
                    .senderKey = aliceEncryption.publicKey,
                    .c1 = cm::ciphertextC1(*senderAmount),
                    .c2 =
                        {cm::ciphertextC2(*senderAmount),
                         cm::ciphertextC2(*destinationAmount),
                         cm::ciphertextC2(*issuerAmount),
                         cm::ciphertextC2(*auditorAmount)},
                    .amountCommitment = *amountCommitment,
                    .balanceCommitment = *balanceCommitment,
                    .balanceC1 = cm::ciphertextC1(*aliceSpending),
                    .balanceC2 = cm::ciphertextC2(*aliceSpending)};
                cm::SendWitness const sendWitness{
                    .m = amount,
                    .r = sendRandomness,
                    .b = aliceBalance,
                    .rho = balanceBlinding,
                    .sk = aliceEncryption.secret};
                auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(ctx));
                auto const range = cm::proveAggregatedBulletproof(
                    *amountCommitment,
                    *remainderCommitment,
                    amount,
                    sendRandomness,
                    aliceBalance - amount,
                    remainderBlinding,
                    asSlice(ctx));
                if (!BEAST_EXPECT(sigma && range))
                    return json::Value{};
                send[sfZKProof] = joinedHex(*sigma, *range);
                return send;
            };

            // No CanTransfer on issuance.
            {
                auto send = buildSend(bob, env.seq(alice));
                if (!BEAST_EXPECT(send.isObject()))
                    return;
                env(send, Ter(tecNO_AUTH));
            }

            // Missing destination account.
            {
                auto send = buildSend(carol, env.seq(alice));
                if (!BEAST_EXPECT(send.isObject()))
                    return;
                env(send, Ter(tecNO_TARGET));
            }

            // Issuer cannot Send (dedicated-account model).
            {
                json::Value send;
                send[jss::TransactionType] = jss::ConfidentialMPTSend;
                send[sfAccount] = issuer.human();
                send[sfDestination] = bob.human();
                send[sfMPTokenIssuanceID] = to_string(issuanceID);
                send[sfSenderEncryptedAmount] = hex(*senderAmount);
                send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
                send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
                send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
                send[sfAmountCommitment] = hex(*amountCommitment);
                send[sfBalanceCommitment] = hex(*balanceCommitment);
                send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
                setConfidentialFee(send);
                env(send, Ter(temMALFORMED));
            }

            // Enable transfer so proof verification is reached, then corrupt the proof.
            {
                Account const issuer2{"proofIssuer"};
                Account const alice2{"proofAlice"};
                Account const bob2{"proofBob"};
                MPTTester mpt2(env, issuer2, {.holders = {alice2, bob2}});
                mpt2.create(
                    {.maxAmt = 100,
                     .authorize = MPTCreate::allHolders,
                     .pay = {{{alice2, bob2}, 40}},
                     .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
                auto const id2 = mpt2.issuanceID();
                auto const isk = key(111);
                auto const ask = key(113);
                auto const aek = key(115);
                auto const bek = key(117);
                json::Value sk;
                sk[jss::TransactionType] = jss::MPTokenIssuanceSet;
                sk[sfAccount] = issuer2.human();
                sk[sfMPTokenIssuanceID] = to_string(id2);
                sk[sfIssuerEncryptionKey] = hex(isk.publicKey);
                sk[sfAuditorEncryptionKey] = hex(ask.publicKey);
                env(sk);
                env(convertTx(alice2, id2, 40, aek, isk, ask, scalar(7), env.seq(alice2)));
                env(mergeTx(alice2, id2));
                env(convertTx(bob2, id2, 0, bek, isk, ask, scalar(9), env.seq(bob2)));

                auto const aliceMpt2 = env.le(keylet::mptoken(id2, alice2.id()));
                if (!BEAST_EXPECT(aliceMpt2))
                    return;
                auto const spending2 =
                    cm::parseCiphertext((*aliceMpt2)[sfConfidentialBalanceSpending]);
                if (!BEAST_EXPECT(spending2))
                    return;

                auto const r = scalar(21);
                auto const rho = scalar(23);
                auto const rem = scalar(3);
                std::uint64_t constexpr amt = 5;
                std::uint64_t constexpr bal = 40;
                auto const sAmt = cm::encryptAmount(aek.publicKey, amt, r);
                auto const dAmt = cm::encryptAmount(bek.publicKey, amt, r);
                auto const iAmt = cm::encryptAmount(isk.publicKey, amt, r);
                auto const auAmt = cm::encryptAmount(ask.publicKey, amt, r);
                auto const aCm = cm::pedersenCommit(amt, r);
                auto const bCm = cm::pedersenCommit(bal, rho);
                if (!BEAST_EXPECT(sAmt && dAmt && iAmt && auAmt && aCm && bCm))
                    return;

                json::Value send;
                send[jss::TransactionType] = jss::ConfidentialMPTSend;
                send[sfAccount] = alice2.human();
                send[sfDestination] = bob2.human();
                send[sfMPTokenIssuanceID] = to_string(id2);
                send[sfSenderEncryptedAmount] = hex(*sAmt);
                send[sfDestinationEncryptedAmount] = hex(*dAmt);
                send[sfIssuerEncryptedAmount] = hex(*iAmt);
                send[sfAuditorEncryptedAmount] = hex(*auAmt);
                send[sfAmountCommitment] = hex(*aCm);
                send[sfBalanceCommitment] = hex(*bCm);
                // Correct length, all-zero proof bytes → verification fails.
                send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
                setConfidentialFee(send);
                env(send, Ter(tecBAD_PROOF));
                (void)rem;
                (void)spending2;
            }
        }
    }



    void
    testRequirementEvidence()
    {
        testcase("requirement evidence: stale CBS version and auditor permission gates");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);

        // §8: Send proof must bind the current ConfidentialBalanceVersion.
        // A stale version in the TransactionContextID must fail (tecBAD_PROOF).
        {
            Account const issuer{"reqVerIssuer"};
            Account const alice{"reqVerAlice"};
            Account const bob{"reqVerBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(201);
            auto const auditorEncryption = key(203);
            auto const aliceEncryption = key(205);
            auto const bobEncryption = key(207);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                alice,
                issuanceID,
                40,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTx(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(5),
                env.seq(bob)));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 5;
            std::uint64_t constexpr aliceBalance = 40;
            auto const sendRandomness = scalar(17);
            auto const balanceBlinding = scalar(19);
            auto const remainderBlinding = scalar(2);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment = cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const staleVersion = aliceVersion + 1;
            auto const ctx =
                sendContext(alice, issuanceID, env.seq(alice), bob, staleVersion);
            cm::SendPublicInput sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     bobEncryption.publicKey,
                     issuerEncryption.publicKey,
                     auditorEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount),
                     cm::ciphertextC2(*auditorAmount)},
                .amountCommitment = *amountCommitment,
                .balanceCommitment = *balanceCommitment,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending)};
            cm::SendWitness const sendWitness{
                .m = amount,
                .r = sendRandomness,
                .b = aliceBalance,
                .rho = balanceBlinding,
                .sk = aliceEncryption.secret};
            auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(ctx));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(ctx));
            if (!BEAST_EXPECT(sigma && range))
                return;

            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            send[sfZKProof] = joinedHex(*sigma, *range);
            setConfidentialFee(send);
            env(send, Ter(tecBAD_PROOF));
        }

        // §7: Convert with an auditor key configured requires AuditorEncryptedAmount.
        {
            Account const issuer{"reqAudIssuer"};
            Account const alice{"reqAudAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(211);
            auto const auditorEncryption = key(213);
            auto const aliceEncryption = key(215);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            // Issuer-only Convert helper omits AuditorEncryptedAmount.
            env(convertTxIssuerOnly(
                    alice,
                    issuanceID,
                    3,
                    aliceEncryption,
                    issuerEncryption,
                    scalar(7),
                    env.seq(alice)),
                Ter(tecNO_PERMISSION));
        }

        // §7: Convert must not include AuditorEncryptedAmount when no auditor key.
        {
            Account const issuer{"reqNoAudIssuer"};
            Account const alice{"reqNoAudAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(221);
            auto const auditorEncryption = key(223);
            auto const aliceEncryption = key(225);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            // Intentionally omit AuditorEncryptionKey.
            env(setKeys);

            env(convertTx(
                    alice,
                    issuanceID,
                    3,
                    aliceEncryption,
                    issuerEncryption,
                    auditorEncryption,
                    scalar(9),
                    env.seq(alice)),
                Ter(tecNO_PERMISSION));
        }

        // §10: ConvertBack with auditor configured requires AuditorEncryptedAmount.
        {
            Account const issuer{"reqCbAudIssuer"};
            Account const alice{"reqCbAudAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(231);
            auto const auditorEncryption = key(233);
            auto const aliceEncryption = key(235);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            env(convertTx(
                alice,
                issuanceID,
                5,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(11),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 2;
            auto const withdrawRandomness = scalar(13);
            auto const withdrawBlinding = scalar(15);
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(amount, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(0, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && withdrawBalanceCommitment &&
                    withdrawRemainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const withdrawCtx =
                convertBackContext(alice, issuanceID, env.seq(alice), aliceVersion);
            cm::ConvertBackPublicInput const withdrawInput{
                .holderKey = aliceEncryption.publicKey,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending),
                .balanceCommitment = *withdrawBalanceCommitment};
            cm::ConvertBackWitness const withdrawWitness{
                .b = amount, .rho = withdrawBlinding, .sk = aliceEncryption.secret};
            auto const withdrawSigma =
                cm::proveConvertBackSigma(withdrawInput, withdrawWitness, asSlice(withdrawCtx));
            auto const withdrawRange = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment, 0, withdrawBlinding, asSlice(withdrawCtx));
            if (!BEAST_EXPECT(withdrawSigma && withdrawRange))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = std::to_string(amount);
            convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
            // Auditor key is configured; omitting AuditorEncryptedAmount must fail.
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecNO_PERMISSION));
        }
    }

    void
    testVersionWrap()
    {
        testcase("MergeInbox wraps ConfidentialBalanceVersion at UINT32_MAX");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"wrapIssuer"};
        Account const alice{"wrapAlice"};

        MPTTester mpt(env, issuer, {.holders = {alice}});
        mpt.create(
            {.maxAmt = 50,
             .authorize = MPTCreate::allHolders,
             .pay = {{{alice}, 10}},
             .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();
        auto const issuerEncryption = key(121);
        auto const auditorEncryption = key(123);
        auto const aliceEncryption = key(125);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
        env(setKeys);

        // Leave a non-zero public MPTAmount so SLE(*sle, key) can re-apply the
        // MPToken template (SoeDefault fields may not be explicitly zero).
        env(convertTx(
            alice,
            issuanceID,
            5,
            aliceEncryption,
            issuerEncryption,
            auditorEncryption,
            scalar(3),
            env.seq(alice)));
        env(mergeTx(alice, issuanceID));

        // Force the spending-balance version to UINT32_MAX without closing the
        // ledger, then merge the (empty) inbox so the wrap is observable.
        BEAST_EXPECT(env.app().getOpenLedger().modify(
            [&](OpenView& view, beast::Journal) {
                auto const sle = view.read(keylet::mptoken(issuanceID, alice.id()));
                if (!sle)
                    return false;
                auto replacement = std::make_shared<SLE>(*sle, sle->key());
                (*replacement)[sfConfidentialBalanceVersion] =
                    std::numeric_limits<std::uint32_t>::max();
                view.rawReplace(replacement);
                return true;
            }));

        env(mergeTx(alice, issuanceID));
        auto const after = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(after))
            return;
        BEAST_EXPECT((*after)[sfConfidentialBalanceVersion] == 0);
    }


public:
    void
    run() override
    {
        testIssuancePolicy();
        testFlow();
        testNegativePaths();
        testFeesAndPolicyFailures();
        testAmendmentDisabled();
        testConvertDuplicateKey();
        testPermissionGates();
        testProtocolFailures();
        testRequirementEvidence();
        testVersionWrap();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTFlow, app, xrpl);

}  // namespace xrpl
