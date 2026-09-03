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
#include <chrono>
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
        auto const issuanceAfterConvert = env.le(keylet::mptIssuance(issuanceID));
        if (!BEAST_EXPECT(aliceMpt && issuanceAfterConvert))
            return;
        BEAST_EXPECT((*issuanceAfterConvert)[sfOutstandingAmount] == 100);
        BEAST_EXPECT(
            (*issuanceAfterConvert)[~sfConfidentialOutstandingAmount].value_or(0) == 100);
        BEAST_EXPECT((*aliceMpt)[~sfMPTAmount].value_or(0) == 0);
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

        // XLS §8.3.2.1: an unaccepted credential is invalid even when supplied.
        char const credentialType[] = "confidential-mpt";
        env(credentials::create(alice, issuer, credentialType));
        env.close();
        auto const credential =
            credentials::ledgerEntry(env, alice, issuer, credentialType);
        auto const credentialID = credential[jss::result][jss::index].asString();

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
        env(send, credentials::Ids({credentialID}), Ter(tecBAD_CREDENTIALS));

        // Accepted credentials are still rejected once expired.
        char const expiredCredentialType[] = "confidential-mpt-expired";
        auto expiredCredentialTx =
            credentials::create(alice, issuer, expiredCredentialType);
        expiredCredentialTx[sfExpiration.jsonName] =
            env.current()->header().parentCloseTime.time_since_epoch().count() + 20;
        env(expiredCredentialTx);
        env.close();
        auto const expiredCredential =
            credentials::ledgerEntry(env, alice, issuer, expiredCredentialType);
        auto const expiredCredentialID =
            expiredCredential[jss::result][jss::index].asString();
        env(credentials::accept(alice, issuer, expiredCredentialType));
        env.close();
        env(deposit::authCredentials(bob, {{issuer, expiredCredentialType}}));
        env.close(std::chrono::seconds{30});

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
        env(send, credentials::Ids({expiredCredentialID}), Ter(tecEXPIRED));

        // Once accepted and preauthorized by credential type, DepositAuth allows Send.
        env(credentials::accept(alice, issuer, credentialType));
        env.close();
        env(deposit::authCredentials(bob, {{issuer, credentialType}}));
        env.close();
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
        env(send, credentials::Ids({credentialID}));

        env(mergeTx(bob, issuanceID));
        auto const bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
        auto const issuanceAfterSend = env.le(keylet::mptIssuance(issuanceID));
        if (!BEAST_EXPECT(bobMpt && issuanceAfterSend))
            return;
        BEAST_EXPECT((*issuanceAfterSend)[sfOutstandingAmount] == 100);
        BEAST_EXPECT(
            (*issuanceAfterSend)[~sfConfidentialOutstandingAmount].value_or(0) == 100);
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
        auto const bobAfterConvertBack = env.le(keylet::mptoken(issuanceID, bob.id()));
        auto const issuanceAfterConvertBack = env.le(keylet::mptIssuance(issuanceID));
        if (!BEAST_EXPECT(
                aliceAfterSend && bobAfterConvertBack && issuanceAfterConvertBack))
            return;
        BEAST_EXPECT((*issuanceAfterConvertBack)[sfOutstandingAmount] == 100);
        BEAST_EXPECT(
            (*issuanceAfterConvertBack)[~sfConfidentialOutstandingAmount].value_or(0) == 70);
        BEAST_EXPECT((*bobAfterConvertBack)[sfMPTAmount] == amount);
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
    testInboxRerandomizeAndConvertBackVersion()
    {
        testcase(
            "requirement evidence: Send inbox re-randomization and ConvertBack "
            "stale CBS version");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);

        // Updated §3.8 / XLS §8.4: destination inbox must be re-randomized with
        // Fiat–Shamir e after the homomorphic credit. A credit-only inbox
        // (old ⊕ DestEnc) must not equal the post-Send inbox.
        {
            Account const issuer{"rrIssuer"};
            Account const alice{"rrAlice"};
            Account const bob{"rrBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(301);
            auto const auditorEncryption = key(303);
            auto const aliceEncryption = key(305);
            auto const bobEncryption = key(307);

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
            auto const bobMptBefore = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(aliceMpt && bobMptBefore))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            auto const bobInboxBefore =
                cm::parseCiphertext((*bobMptBefore)[sfConfidentialBalanceInbox]);
            if (!BEAST_EXPECT(aliceSpending && bobInboxBefore))
                return;

            std::uint64_t constexpr amount = 7;
            std::uint64_t constexpr aliceBalance = 40;
            auto const sendRandomness = scalar(41);
            auto const balanceBlinding = scalar(43);
            // Must satisfy remBlinding = balanceBlinding - sendRandomness so
            // PC_rem == PC_b - PC_m for aggregated Bulletproof verification.
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

            // Credit-only prediction (no re-randomization).
            auto const creditOnly =
                cm::ciphertextAdd(*bobInboxBefore, *destinationAmount);
            if (!BEAST_EXPECT(creditOnly))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const ctx =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
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
            env(send);

            auto const bobMptAfter = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMptAfter))
                return;
            auto const bobInboxAfter =
                cm::parseCiphertext((*bobMptAfter)[sfConfidentialBalanceInbox]);
            if (!BEAST_EXPECT(bobInboxAfter))
                return;

            // Re-randomization must change the inbox relative to credit-only.
            BEAST_EXPECT(*bobInboxAfter != *creditOnly);
            BEAST_EXPECT(*bobInboxAfter != *bobInboxBefore);

            // Merge must still succeed on the re-randomized inbox.
            env(mergeTx(bob, issuanceID));
            auto const bobMerged = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMerged))
                return;
            auto const bobSpending =
                cm::parseCiphertext((*bobMerged)[sfConfidentialBalanceSpending]);
            auto const bobInboxReset =
                cm::parseCiphertext((*bobMerged)[sfConfidentialBalanceInbox]);
            auto const expectedZero = confidentialMPTEncryptedZero(
                bobEncryption.publicKey, bob.id(), issuer.id(), issuanceID);
            if (!BEAST_EXPECT(bobSpending && bobInboxReset && expectedZero))
                return;
            BEAST_EXPECT(*bobInboxReset == *expectedZero);
        }

        // Updated §4.7: ConvertBack TransactionContextID binds CBS version.
        // A stale version must fail proof verification (tecBAD_PROOF).
        {
            Account const issuer{"cbVerIssuer"};
            Account const alice{"cbVerAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(311);
            auto const auditorEncryption = key(313);
            auto const aliceEncryption = key(315);

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
                scalar(7),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 3;
            auto const withdrawRandomness = scalar(17);
            auto const withdrawBlinding = scalar(19);
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const auditorWithdrawal =
                cm::encryptAmount(auditorEncryption.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(amount, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(0, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const staleVersion = aliceVersion + 1;
            auto const withdrawCtx =
                convertBackContext(alice, issuanceID, env.seq(alice), staleVersion);
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
            convertBack[sfAuditorEncryptedAmount] = hex(*auditorWithdrawal);
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecBAD_PROOF));
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

    void
    testClawbackFrontRunning()
    {
        testcase(
            "requirement evidence: Updated Remark 5.1 clawback front-running "
            "and clawback under lock");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);

        // Updated Remark 5.1: clawback proofs bind the concrete issuer
        // ciphertext. An intervening Send that changes IssuerEncryptedBalance
        // must invalidate a previously prepared clawback proof (tecBAD_PROOF).
        {
            Account const issuer{"frIssuer"};
            Account const alice{"frAlice"};
            Account const bob{"frBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(401);
            auto const auditorEncryption = key(403);
            auto const aliceEncryption = key(405);
            auto const bobEncryption = key(407);

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

            auto const aliceBefore = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceBefore))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceBefore)[sfConfidentialBalanceSpending]);
            auto const aliceIssuerBefore =
                cm::parseCiphertext((*aliceBefore)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(aliceSpending && aliceIssuerBefore))
                return;

            std::uint64_t constexpr aliceBalance = 40;
            std::uint64_t constexpr sendAmount = 5;
            auto const staleClawCtx =
                clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
            cm::ClawbackPublicInput const staleClawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*aliceIssuerBefore),
                .c2 = cm::ciphertextC2(*aliceIssuerBefore),
                .m = aliceBalance};
            auto const staleClawProof = cm::proveClawback(
                staleClawInput, issuerEncryption.secret, asSlice(staleClawCtx));
            if (!BEAST_EXPECT(staleClawProof))
                return;

            json::Value staleClawback;
            staleClawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            staleClawback[sfAccount] = issuer.human();
            staleClawback[sfHolder] = alice.human();
            staleClawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            staleClawback[sfMPTAmount] = std::to_string(aliceBalance);
            staleClawback[sfZKProof] = hex(*staleClawProof);
            setConfidentialFee(staleClawback);

            // Intervening Send changes Alice's issuer ciphertext before clawback.
            auto const sendRandomness = scalar(41);
            auto const balanceBlinding = scalar(43);
            auto const remainderBlinding = scalar(2);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, sendAmount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, sendAmount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, sendAmount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, sendAmount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(sendAmount, sendRandomness);
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - sendAmount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceBefore)[~sfConfidentialBalanceVersion].value_or(0);
            auto const sendCtx =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
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
                .m = sendAmount,
                .r = sendRandomness,
                .b = aliceBalance,
                .rho = balanceBlinding,
                .sk = aliceEncryption.secret};
            auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                sendAmount,
                sendRandomness,
                aliceBalance - sendAmount,
                remainderBlinding,
                asSlice(sendCtx));
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
            env(send);

            auto const aliceAfterSend = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceAfterSend))
                return;
            auto const aliceIssuerAfter =
                cm::parseCiphertext((*aliceAfterSend)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(aliceIssuerAfter))
                return;
            BEAST_EXPECT(*aliceIssuerAfter != *aliceIssuerBefore);

            // Stale clawback (bound to pre-Send ciphertext / full 40) fails.
            env(staleClawback, Ter(tecBAD_PROOF));

            // Fresh clawback over the post-Send remainder succeeds after
            // amount/plaintext mismatch rejections. tec* results consume
            // sequence, so each proof must bind the issuer sequence used
            // at submit time.
            std::uint64_t constexpr remainder = aliceBalance - sendAmount;
            cm::ClawbackPublicInput const freshClawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*aliceIssuerAfter),
                .c2 = cm::ciphertextC2(*aliceIssuerAfter),
                .m = remainder};

            // Updated Sec 5.5/5.7: public input m is the tx amount. A valid
            // remainder proof submitted with a mismatched amount must fail.
            {
                auto const wrongAmtCtx =
                    clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
                auto const wrongAmtProof = cm::proveClawback(
                    freshClawInput, issuerEncryption.secret, asSlice(wrongAmtCtx));
                if (!BEAST_EXPECT(wrongAmtProof))
                    return;
                json::Value wrongAmount;
                wrongAmount[jss::TransactionType] = jss::ConfidentialMPTClawback;
                wrongAmount[sfAccount] = issuer.human();
                wrongAmount[sfHolder] = alice.human();
                wrongAmount[sfMPTokenIssuanceID] = to_string(issuanceID);
                wrongAmount[sfMPTAmount] = std::to_string(remainder - 1);
                wrongAmount[sfZKProof] = hex(*wrongAmtProof);
                setConfidentialFee(wrongAmount);
                env(wrongAmount, Ter(tecBAD_PROOF));
            }

            // A proof for the wrong plaintext against the real ciphertext
            // must also fail even when the tx amount matches that wrong m.
            {
                auto const wrongMCtx =
                    clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
                cm::ClawbackPublicInput const wrongMInput{
                    .issuerKey = issuerEncryption.publicKey,
                    .c1 = cm::ciphertextC1(*aliceIssuerAfter),
                    .c2 = cm::ciphertextC2(*aliceIssuerAfter),
                    .m = remainder - 1};
                auto const wrongMProof = cm::proveClawback(
                    wrongMInput, issuerEncryption.secret, asSlice(wrongMCtx));
                if (!BEAST_EXPECT(wrongMProof))
                    return;
                json::Value wrongPlaintext;
                wrongPlaintext[jss::TransactionType] = jss::ConfidentialMPTClawback;
                wrongPlaintext[sfAccount] = issuer.human();
                wrongPlaintext[sfHolder] = alice.human();
                wrongPlaintext[sfMPTokenIssuanceID] = to_string(issuanceID);
                wrongPlaintext[sfMPTAmount] = std::to_string(remainder - 1);
                wrongPlaintext[sfZKProof] = hex(*wrongMProof);
                setConfidentialFee(wrongPlaintext);
                env(wrongPlaintext, Ter(tecBAD_PROOF));
            }

            auto const freshClawCtx =
                clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
            auto const freshClawProof = cm::proveClawback(
                freshClawInput, issuerEncryption.secret, asSlice(freshClawCtx));
            if (!BEAST_EXPECT(freshClawProof))
                return;

            json::Value freshClawback;
            freshClawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            freshClawback[sfAccount] = issuer.human();
            freshClawback[sfHolder] = alice.human();
            freshClawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            freshClawback[sfMPTAmount] = std::to_string(remainder);
            freshClawback[sfZKProof] = hex(*freshClawProof);
            setConfidentialFee(freshClawback);
            env(freshClawback);

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            auto const aliceFinal = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(issuance && aliceFinal))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == sendAmount);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == sendAmount);
        }

        // Remark 5.1 recommends locking before clawback. Lock blocks holder
        // Send/Merge/ConvertBack (tecLOCKED) but must still allow issuer clawback.
        {
            Account const issuer{"lkIssuer"};
            Account const alice{"lkAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback | tfMPTCanLock |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(411);
            auto const auditorEncryption = key(413);
            auto const aliceEncryption = key(415);

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
                scalar(7),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            json::Value lockHolder;
            lockHolder[jss::TransactionType] = jss::MPTokenIssuanceSet;
            lockHolder[sfAccount] = issuer.human();
            lockHolder[sfMPTokenIssuanceID] = to_string(issuanceID);
            lockHolder[sfHolder] = alice.human();
            env(lockHolder, Txflags(tfMPTLock));
            env.close();

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt && aliceMpt->isFlag(lsfMPTLocked)))
                return;
            auto const aliceIssuer =
                cm::parseCiphertext((*aliceMpt)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(aliceIssuer))
                return;

            std::uint64_t constexpr amount = 20;
            auto const clawCtx =
                clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
            cm::ClawbackPublicInput const clawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*aliceIssuer),
                .c2 = cm::ciphertextC2(*aliceIssuer),
                .m = amount};
            auto const clawProof =
                cm::proveClawback(clawInput, issuerEncryption.secret, asSlice(clawCtx));
            if (!BEAST_EXPECT(clawProof))
                return;

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = std::to_string(amount);
            clawback[sfZKProof] = hex(*clawProof);
            setConfidentialFee(clawback);
            env(clawback);

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(issuance))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 0);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 0);
            // xls-0096 Sec 11.1/11.4: clawback burns supply; issuer is not
            // credited a public MPToken balance.
            BEAST_EXPECT(!env.le(keylet::mptoken(issuanceID, issuer.id())));
        }

        // xls-0096 Sec 11.3.2.6: MPTAmount exceeding global COA fails before
        // proof verification (tecINSUFFICIENT_FUNDS).
        {
            Account const issuer{"coaIssuer"};
            Account const alice{"coaAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(421);
            auto const auditorEncryption = key(423);
            auto const aliceEncryption = key(425);

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
                10,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceIssuer =
                cm::parseCiphertext((*aliceMpt)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(aliceIssuer))
                return;

            // Proof for the true balance (10), but declare amount 11 > COA.
            auto const clawCtx =
                clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
            cm::ClawbackPublicInput const clawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*aliceIssuer),
                .c2 = cm::ciphertextC2(*aliceIssuer),
                .m = 10};
            auto const clawProof =
                cm::proveClawback(clawInput, issuerEncryption.secret, asSlice(clawCtx));
            if (!BEAST_EXPECT(clawProof))
                return;

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "11";
            clawback[sfZKProof] = hex(*clawProof);
            setConfidentialFee(clawback);
            env(clawback, Ter(tecINSUFFICIENT_FUNDS));
        }
    }

    void
    testAdditionalRequirementEvidence()
    {
        testcase(
            "requirement evidence: DepositAuth preauth, Convert bad blinding, "
            "zero Convert supply, TransferFee Send defense");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 8.3.2.1: DepositAuth can be satisfied by account preauthorization
        // (deposit::auth) without CredentialIDs.
        {
            Env env(*this, features);
            Account const issuer{"daIssuer"};
            Account const alice{"daAlice"};
            Account const bob{"daBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 30}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(501);
            auto const auditorEncryption = key(503);
            auto const aliceEncryption = key(505);
            auto const bobEncryption = key(507);

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
                30,
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

            std::uint64_t constexpr amount = 4;
            std::uint64_t constexpr aliceBalance = 30;
            auto const sendRandomness = scalar(41);
            auto const balanceBlinding = scalar(43);
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
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const sendCtx =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
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
            auto const sigma =
                cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
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

            // testFlow already covers tecNO_PERMISSION under DepositAuth.
            // Here: account preauth (deposit::auth) alone permits Send.
            env(fset(bob, asfDepositAuth));
            env(deposit::auth(bob, alice));
            env.close();
            auto const sendCtx2 =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
            auto const sigma2 =
                cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx2));
            auto const range2 = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(sendCtx2));
            if (!BEAST_EXPECT(sigma2 && range2))
                return;
            send[sfZKProof] = joinedHex(*sigma2, *range2);
            env(send);
        }

        // Sec 7.3.2.4: Convert with mismatched BlindingFactor → tecBAD_PROOF.
        {
            Env env(*this, features);
            Account const issuer{"bfIssuer"};
            Account const alice{"bfAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(511);
            auto const auditorEncryption = key(513);
            auto const aliceEncryption = key(515);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            auto tx = convertTx(
                alice,
                issuanceID,
                5,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(7),
                env.seq(alice));
            tx[sfBlindingFactor] = hex(scalar(9));
            env(tx, Ter(tecBAD_PROOF));
        }

        // Updated Sec 2.1 / xls Sec 7.5: zero-amount Convert initializes keys
        // without changing OA/COA; spending balance is EncZero.
        {
            Env env(*this, features);
            Account const issuer{"zIssuer"};
            Account const alice{"zAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(521);
            auto const auditorEncryption = key(523);
            auto const aliceEncryption = key(525);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            auto const before = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(before))
                return;
            auto const oaBefore = (*before)[sfOutstandingAmount];
            auto const coaBefore =
                (*before)[~sfConfidentialOutstandingAmount].value_or(0);

            env(convertTx(
                alice,
                issuanceID,
                0,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(2),
                env.seq(alice)));

            auto const afterConvert = env.le(keylet::mptIssuance(issuanceID));
            auto const aliceAfterConvert =
                env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(afterConvert && aliceAfterConvert))
                return;
            BEAST_EXPECT((*afterConvert)[sfOutstandingAmount] == oaBefore);
            BEAST_EXPECT(
                (*afterConvert)[~sfConfidentialOutstandingAmount].value_or(0) ==
                coaBefore);
            BEAST_EXPECT(aliceAfterConvert->isFieldPresent(sfHolderEncryptionKey));
            BEAST_EXPECT((*aliceAfterConvert)[~sfMPTAmount].value_or(0) == 10);

            // Convert initializes spending to EncZero and credits Enc(0,r)
            // into inbox. Only spending equals the deterministic EncZero
            // ciphertext before MergeInbox.
            auto const expectedZero = confidentialMPTEncryptedZero(
                aliceEncryption.publicKey, alice.id(), issuer.id(), issuanceID);
            if (!BEAST_EXPECT(expectedZero))
                return;
            auto const spending = cm::parseCiphertext(
                (*aliceAfterConvert)[sfConfidentialBalanceSpending]);
            auto const inbox = cm::parseCiphertext(
                (*aliceAfterConvert)[sfConfidentialBalanceInbox]);
            BEAST_EXPECT(spending && *spending == *expectedZero);
            BEAST_EXPECT(inbox && *inbox != *expectedZero);
        }

        // Sec 6.4 / Send defense-in-depth: non-zero TransferFee on a confidential
        // issuance rejects Send with tecNO_PERMISSION. Valid create/set cannot
        // reach this state, so poke the open ledger.
        {
            Env env(*this, features);
            Account const issuer{"tfIssuer"};
            Account const alice{"tfAlice"};
            Account const bob{"tfBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(531);
            auto const auditorEncryption = key(533);
            auto const aliceEncryption = key(535);
            auto const bobEncryption = key(537);

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

            BEAST_EXPECT(env.app().getOpenLedger().modify(
                [&](OpenView& view, beast::Journal) {
                    auto const sle = view.read(keylet::mptIssuance(issuanceID));
                    if (!sle)
                        return false;
                    auto replacement = std::make_shared<SLE>(*sle, sle->key());
                    replacement->setFieldU16(sfTransferFee, 1);
                    view.rawReplace(replacement);
                    return true;
                }));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 2;
            std::uint64_t constexpr aliceBalance = 20;
            auto const sendRandomness = scalar(41);
            auto const balanceBlinding = scalar(43);
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
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const sendCtx =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
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
            auto const sigma =
                cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
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
            env(send, Ter(tecNO_PERMISSION));
        }
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
        testInboxRerandomizeAndConvertBackVersion();
        testVersionWrap();
        testClawbackFrontRunning();
        testAdditionalRequirementEvidence();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTFlow, app, xrpl);

}  // namespace xrpl
