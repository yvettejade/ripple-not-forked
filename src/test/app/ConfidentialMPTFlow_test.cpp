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

    static bool
    ciphertextEncodes(
        cm::Ciphertext const& ciphertext,
        cm::Scalar const& secret,
        std::uint64_t amount)
    {
        auto const shared =
            cm::pointMul(cm::ciphertextC1(ciphertext), secret);
        if (!shared)
            return false;
        auto const c2 = cm::ciphertextC2(ciphertext);
        if (amount == 0)
            return *shared == c2;
        auto const amountPoint = cm::pointMulBase(scalar(amount));
        if (!amountPoint)
            return false;
        auto const expected = cm::pointAdd(*amountPoint, *shared);
        return expected && *expected == c2;
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

        // CredentialIDs on Send require featureCredentials independently of
        // featureConfidentialTransfer.
        auto credentialFeatures = testableAmendments();
        credentialFeatures.set(featureConfidentialTransfer);
        credentialFeatures.set(featureDynamicMPT);
        Env credentialEnv(*this, credentialFeatures - featureCredentials);
        Account const credentialAlice{"credFeatureAlice"};
        Account const credentialBob{"credFeatureBob"};
        credentialEnv.fund(XRP(1'000), credentialAlice, credentialBob);

        auto const r = scalar(13);
        auto const senderAmount =
            cm::encryptAmount(key(15).publicKey, 1, r);
        auto const destinationAmount =
            cm::encryptAmount(key(17).publicKey, 1, r);
        auto const issuerAmount =
            cm::encryptAmount(key(19).publicKey, 1, r);
        auto const amountCommitment = cm::pedersenCommit(1, r);
        auto const balanceCommitment = cm::pedersenCommit(1, scalar(21));
        if (!BEAST_EXPECT(
                senderAmount && destinationAmount && issuerAmount &&
                amountCommitment && balanceCommitment))
            return;

        json::Value send;
        send[jss::TransactionType] = jss::ConfidentialMPTSend;
        send[sfAccount] = credentialAlice.human();
        send[sfDestination] = credentialBob.human();
        send[sfMPTokenIssuanceID] =
            to_string(makeMptID(1, credentialAlice));
        send[sfSenderEncryptedAmount] = hex(*senderAmount);
        send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
        send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        send[sfAmountCommitment] = hex(*amountCommitment);
        send[sfBalanceCommitment] = hex(*balanceCommitment);
        send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
        setConfidentialFee(send);
        credentialEnv(
            send,
            credentials::Ids({uint256{1}}),
            Ter(temDISABLED));
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

        // After COA drains to 0 (SoeDefault removes the field), key re-upload
        // must still fail via write-once (§12.4.2.2), not because COA is present.
        {
            Account const issuer{"drainIssuer"};
            Account const alice{"drainAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(77);
            auto const aliceEncryption = key(79);
            json::Value setIssuer;
            setIssuer[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setIssuer[sfAccount] = issuer.human();
            setIssuer[sfMPTokenIssuanceID] = to_string(issuanceID);
            setIssuer[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setIssuer);

            std::uint64_t constexpr amount = 10;
            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                amount,
                aliceEncryption,
                issuerEncryption,
                scalar(8),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            auto const withdrawRandomness = scalar(17);
            auto const withdrawBlinding = scalar(19);
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
            auto const withdrawSigma = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(withdrawCtx));
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
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);
            env(convertBack);

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(issuance))
                return;
            BEAST_EXPECT(!issuance->isFieldPresent(sfConfidentialOutstandingAmount));
            BEAST_EXPECT((*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 0);
            BEAST_EXPECT(
                strHex(issuance->getFieldVL(sfIssuerEncryptionKey)) ==
                hex(issuerEncryption.publicKey));

            // Issuer key already stored → tecNO_PERMISSION even though COA field is gone.
            json::Value reupload;
            reupload[jss::TransactionType] = jss::MPTokenIssuanceSet;
            reupload[sfAccount] = issuer.human();
            reupload[sfMPTokenIssuanceID] = to_string(issuanceID);
            reupload[sfIssuerEncryptionKey] = hex(key(81).publicKey);
            env(reupload, Ter(tecNO_PERMISSION));

            json::Value reuploadBoth;
            reuploadBoth[jss::TransactionType] = jss::MPTokenIssuanceSet;
            reuploadBoth[sfAccount] = issuer.human();
            reuploadBoth[sfMPTokenIssuanceID] = to_string(issuanceID);
            reuploadBoth[sfIssuerEncryptionKey] = hex(key(81).publicKey);
            reuploadBoth[sfAuditorEncryptionKey] = hex(key(83).publicKey);
            env(reuploadBoth, Ter(tecNO_PERMISSION));
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
            "requirement evidence: DepositAuth, Convert proofs, zero Convert, "
            "clawback self-target, destination lock Send");
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

            auto const bobBefore = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobBefore))
                return;
            auto const bobIssuerBefore =
                cm::parseCiphertext((*bobBefore)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(bobIssuerBefore))
                return;

            env(send);

            // Sec 8.4 / Updated Sec 3.2: successful Send increments the sender
            // ConfidentialBalanceVersion and re-randomizes the destination
            // issuer mirror (not credit-only).
            auto const aliceAfter = env.le(keylet::mptoken(issuanceID, alice.id()));
            auto const bobAfter = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(aliceAfter && bobAfter))
                return;
            BEAST_EXPECT(
                (*aliceAfter)[sfConfidentialBalanceVersion] == aliceVersion + 1);
            auto const bobIssuerAfter =
                cm::parseCiphertext((*bobAfter)[sfIssuerEncryptedBalance]);
            BEAST_EXPECT(bobIssuerAfter && *bobIssuerAfter != *bobIssuerBefore);
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

        // Sec 7.3.2.5: Convert with invalid key-registration ZKProof → tecBAD_PROOF.
        {
            Env env(*this, features);
            Account const issuer{"pokIssuer"};
            Account const alice{"pokAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(541);
            auto const auditorEncryption = key(543);
            auto const aliceEncryption = key(545);

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
            tx[sfZKProof] = hex(std::array<std::uint8_t, cm::kKeyRegProofBytes>{});
            env(tx, Ter(tecBAD_PROOF));
        }

        // Sec 11.3.1.3: Clawback Account == Holder → temMALFORMED.
        {
            Env env(*this, features);
            Account const issuer{"selfCbIssuer"};
            Account const alice{"selfCbAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 5}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = issuer.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, cm::kClawbackProofBytes>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(temMALFORMED));
        }

        // Sec 8.3.2.6: destination-only holder lock blocks Send (tecLOCKED;
        // spec names terFROZEN, absent in this tree).
        {
            Env env(*this, features);
            Account const issuer{"dstLockIssuer"};
            Account const alice{"dstLockAlice"};
            Account const bob{"dstLockBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanLock |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(551);
            auto const auditorEncryption = key(553);
            auto const aliceEncryption = key(555);
            auto const bobEncryption = key(557);

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

            json::Value lockBob;
            lockBob[jss::TransactionType] = jss::MPTokenIssuanceSet;
            lockBob[sfAccount] = issuer.human();
            lockBob[sfMPTokenIssuanceID] = to_string(issuanceID);
            lockBob[sfHolder] = bob.human();
            env(lockBob, Txflags(tfMPTLock));
            env.close();

            auto const bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMpt && bobMpt->isFlag(lsfMPTLocked)))
                return;

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 3;
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
            env(send, Ter(tecLOCKED));
        }

        // Sec 6.4 / Send TransferFee defense-in-depth is intentionally not
        // ledger-poked here: issuances can carry an explicit default
        // TransferFee(0), and OpenView SLE copy/applyTemplate rejects that
        // state. Create/Set already refuse non-zero TransferFee on
        // confidential issuances (testIssuancePolicy); ConfidentialMPTSend
        // still contains the matching tecNO_PERMISSION guard.

    }


    void
    testPreclaimCoverageMatrix()
    {
        testcase(
            "preflight/preclaim coverage: Convert field checks, missing objects, "
            "sender lock, auditor asymmetry, MergeInbox gates, Set fee+flag, "
            "destroy after drained COA");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 7.3.1: Convert key/proof pairing, scalar, amount, ciphertext,
        // and missing-issuance failures.
        {
            Env env(*this, features);
            Account const issuer{"pfIssuer"};
            Account const alice{"pfAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(601);
            auto const auditorEncryption = key(603);
            auto const aliceEncryption = key(605);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            auto const base = convertTx(
                alice,
                issuanceID,
                5,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(7),
                env.seq(alice));

            {
                auto tx = base;
                tx.removeMember(sfHolderEncryptionKey.jsonName);
                env(tx, Ter(temMALFORMED));
            }
            {
                auto tx = base;
                tx.removeMember(sfZKProof.jsonName);
                env(tx, Ter(temMALFORMED));
            }
            {
                auto tx = base;
                tx[sfHolderEncryptionKey] = std::string(64, '0');
                env(tx, Ter(temMALFORMED));
            }
            {
                auto tx = base;
                tx[sfBlindingFactor] = std::string(64, '0');
                env(tx, Ter(temMALFORMED));
            }
            {
                auto tx = base;
                tx[sfMPTAmount] = std::to_string(
                    static_cast<std::uint64_t>(kMaxMpTokenAmount) + 1ull);
                env(tx, Ter(temBAD_AMOUNT));
            }
            {
                auto tx = base;
                tx[sfHolderEncryptedAmount] =
                    std::string(cm::kCiphertextBytes * 2, '0');
                env(tx, Ter(temBAD_CIPHERTEXT));
            }
            {
                auto tx = base;
                tx[sfMPTokenIssuanceID] = to_string(makeMptID(1, alice));
                env(tx, Ter(tecOBJECT_NOT_FOUND));
            }
        }

        // Sec 9.2.1: MergeInbox rejects non-confidential issuance and
        // confidentially-uninitialized holders.
        {
            Env env(*this, features);
            Account const issuer{"mergeGateIssuer"};
            Account const alice{"mergeGateAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer});
            env(mergeTx(alice, mpt.issuanceID()), Ter(tecNO_PERMISSION));
        }
        {
            Env env(*this, features);
            Account const issuer{"mergeInitIssuer"};
            Account const alice{"mergeInitAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(key(611).publicKey);
            env(setKeys);
            env(mergeTx(alice, issuanceID), Ter(tecNO_PERMISSION));
        }

        // Sec 6 / 12: same-transaction TransferFee>0 + set confidential flag.
        {
            Env env(*this, features);
            Account const issuer{"feeFlagIssuer"};
            MPTTester mpt(env, issuer);
            mpt.create(
                {.flags = tfMPTCanTransfer,
                 .mutableFlags = tmfMPTCanMutateTransferFee});
            json::Value set;
            set[jss::TransactionType] = jss::MPTokenIssuanceSet;
            set[sfAccount] = issuer.human();
            set[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            set[sfTransferFee] = 1;
            set[sfIssuerEncryptionKey] = hex(key(621).publicKey);
            env(set,
                Txflags(tfMPTSetCanHoldConfidentialBalance),
                Ter(temBAD_TRANSFER_FEE));
        }

        // Sec 8.3.2.6 sender-only lock + Sec 8.3 auditor-required asymmetry.
        {
            Env env(*this, features);
            Account const issuer{"sndGateIssuer"};
            Account const alice{"sndGateAlice"};
            Account const bob{"sndGateBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanLock |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(631);
            auto const auditorEncryption = key(633);
            auto const aliceEncryption = key(635);
            auto const bobEncryption = key(637);

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

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 3;
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

            auto makeSend = [&](bool includeAuditor) {
                json::Value send;
                send[jss::TransactionType] = jss::ConfidentialMPTSend;
                send[sfAccount] = alice.human();
                send[sfDestination] = bob.human();
                send[sfMPTokenIssuanceID] = to_string(issuanceID);
                send[sfSenderEncryptedAmount] = hex(*senderAmount);
                send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
                send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
                if (includeAuditor)
                    send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
                send[sfAmountCommitment] = hex(*amountCommitment);
                send[sfBalanceCommitment] = hex(*balanceCommitment);
                send[sfZKProof] = joinedHex(*sigma, *range);
                setConfidentialFee(send);
                return send;
            };

            // Auditor key present on issuance but omitted from Send.
            env(makeSend(false), Ter(tecNO_PERMISSION));

            json::Value lockAlice;
            lockAlice[jss::TransactionType] = jss::MPTokenIssuanceSet;
            lockAlice[sfAccount] = issuer.human();
            lockAlice[sfMPTokenIssuanceID] = to_string(issuanceID);
            lockAlice[sfHolder] = alice.human();
            env(lockAlice, Txflags(tfMPTLock));
            env.close();
            auto const locked = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(locked && locked->isFlag(lsfMPTLocked)))
                return;
            env(makeSend(true), Ter(tecLOCKED));
        }

        // Sec 8.3: auditor ciphertext forbidden when issuance has no auditor.
        {
            Env env(*this, features);
            Account const issuer{"noAudIssuer"};
            Account const alice{"noAudAlice"};
            Account const bob{"noAudBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(641);
            auto const aliceEncryption = key(643);
            auto const bobEncryption = key(645);
            auto const strayAuditor = key(647);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTxIssuerOnly(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                scalar(5),
                env.seq(bob)));

            std::uint64_t constexpr amount = 2;
            auto const sendRandomness = scalar(11);
            auto const balanceBlinding = scalar(13);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const auditorAmount =
                cm::encryptAmount(strayAuditor.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment = cm::pedersenCommit(20, balanceBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount && auditorAmount &&
                    amountCommitment && balanceCommitment))
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
            // Preclaim rejects auditor asymmetry before proof verification.
            send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
            setConfidentialFee(send);
            env(send, Ter(tecNO_PERMISSION));
        }

        // Sec 11 / 12: after COA and OA are drained, issuance destroy succeeds.
        {
            Env env(*this, features);
            Account const issuer{"drainIssuer"};
            Account const alice{"drainAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(651);
            auto const auditorEncryption = key(653);
            auto const aliceEncryption = key(655);

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
            auto const issuerBal =
                cm::parseCiphertext((*aliceMpt)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(issuerBal))
                return;

            cm::ClawbackPublicInput const clawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*issuerBal),
                .c2 = cm::ciphertextC2(*issuerBal),
                .m = 10};
            auto const clawCtx =
                clawbackContext(issuer, issuanceID, env.seq(issuer), alice);
            auto const clawProof =
                cm::proveClawback(clawInput, issuerEncryption.secret, asSlice(clawCtx));
            if (!BEAST_EXPECT(clawProof))
                return;

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "10";
            clawback[sfZKProof] = hex(*clawProof);
            setConfidentialFee(clawback);
            env(clawback);

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(issuance))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 0);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 0);
            mpt.destroy();
        }
    }


    void
    testLifecycleGateEvidence()
    {
        testcase(
            "lifecycle gates: sender not init, ConvertBack bad blinding, "
            "IssuanceSet duplicate/missing-flag keys, clawback without issuer key");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 8.3.2.2.4: sender must already be confidentially initialized.
        {
            Env env(*this, features);
            Account const issuer{"sndUninitIssuer"};
            Account const alice{"sndUninitAlice"};
            Account const bob{"sndUninitBob"};
            Account const charlie{"sndMissingCharlie"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice, bob}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            env.fund(XRP(1'000), charlie);
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(701);
            auto const auditorEncryption = key(703);
            auto const aliceEncryption = key(705);
            auto const bobEncryption = key(707);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            // Only bob initializes; alice still holds only public MPTAmount.
            env(convertTx(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(3),
                env.seq(bob)));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            BEAST_EXPECT(!aliceMpt->isFieldPresent(sfHolderEncryptionKey));

            // Syntactically sized Send fields; preclaim rejects before proof verify.
            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            auto const r = scalar(11);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, 1, r);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, 1, r);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, 1, r);
            auto const auditorAmount =
                cm::encryptAmount(auditorEncryption.publicKey, 1, r);
            auto const amountCommitment = cm::pedersenCommit(1, r);
            auto const balanceCommitment = cm::pedersenCommit(20, scalar(13));
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount &&
                    auditorAmount && amountCommitment && balanceCommitment))
                return;
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAuditorEncryptedAmount] = hex(*auditorAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
            setConfidentialFee(send);
            env(send, Ter(tecNO_PERMISSION));

            // A public-only MPToken is tecNO_PERMISSION; an absent MPToken
            // remains the existing MPT lifecycle error tecOBJECT_NOT_FOUND.
            send[sfAccount] = charlie.human();
            env(send, Ter(tecOBJECT_NOT_FOUND));
        }

        // Sec 10.4.2.6-8: ConvertBack BlindingFactor must match ciphertexts.
        {
            Env env(*this, features);
            Account const issuer{"cbBlindIssuer"};
            Account const alice{"cbBlindAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(711);
            auto const auditorEncryption = key(713);
            auto const aliceEncryption = key(715);

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

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 5;
            auto const withdrawRandomness = scalar(29);
            auto const withdrawBlinding = scalar(31);
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const auditorWithdrawal =
                cm::encryptAmount(auditorEncryption.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(20, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(20 - amount, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
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
                .b = 20, .rho = withdrawBlinding, .sk = aliceEncryption.secret};
            auto const withdrawSigma =
                cm::proveConvertBackSigma(withdrawInput, withdrawWitness, asSlice(withdrawCtx));
            auto const withdrawRange = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment,
                20 - amount,
                withdrawBlinding,
                asSlice(withdrawCtx));
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
            // Mismatched blinding vs ciphertext randomness.
            convertBack[sfBlindingFactor] = hex(scalar(99));
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecBAD_PROOF));
        }

        // Sec 12.4.2.2 / §12.4.2.3: duplicate issuer key upload, and keys
        // without confidential flag (unless same-tx enable).
        {
            Env env(*this, features);
            Account const issuer{"dupKeyIssuer"};
            MPTTester mpt(env, issuer);
            mpt.create({.flags = tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(721);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            json::Value dupKeys = setKeys;
            dupKeys[sfIssuerEncryptionKey] = hex(key(723).publicKey);
            env(dupKeys, Ter(tecNO_PERMISSION));
        }
        {
            Env env(*this, features);
            Account const issuer{"noFlagKeyIssuer"};
            MPTTester mpt(env, issuer);
            mpt.create({.flags = tfMPTCanTransfer});
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            setKeys[sfIssuerEncryptionKey] = hex(key(725).publicKey);
            env(setKeys, Ter(tecNO_PERMISSION));
        }

        // Sec 11.3.2.4: clawback requires issuance IssuerEncryptionKey.
        {
            Env env(*this, features);
            Account const issuer{"clawNoKeyIssuer"};
            Account const alice{"clawNoKeyAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            // Confidential flag set at create, but no issuer encryption key uploaded.
            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(tecNO_PERMISSION));
        }
    }


    void
    testCredentialObjectMirrorEvidence()
    {
        testcase(
            "requirement evidence: DepositAuth credential mismatches, Send "
            "flag/key gates, Convert without MPToken, ConvertBack object/"
            "auditor gates, auditor mirror postconditions");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 8.3.2.1: accepted credential of a type not in DepositPreauth.
        {
            Env env(*this, features);
            Account const issuer{"credTypeIssuer"};
            Account const alice{"credTypeAlice"};
            Account const bob{"credTypeBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(801);
            auto const auditorEncryption = key(803);
            auto const aliceEncryption = key(805);
            auto const bobEncryption = key(807);

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
            env(fset(bob, asfDepositAuth));

            char const typeA[] = "cred-type-a";
            char const typeB[] = "cred-type-b";
            env(deposit::authCredentials(bob, {{issuer, typeA}}));
            env(credentials::create(alice, issuer, typeB));
            env.close();
            env(credentials::accept(alice, issuer, typeB));
            env.close();
            auto const credB =
                credentials::ledgerEntry(env, alice, issuer, typeB);
            auto const credBId = credB[jss::result][jss::index].asString();

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
            env(send, credentials::Ids({credBId}), Ter(tecNO_PERMISSION));
        }

        // Sec 8.3.2.1: CredentialIDs whose subject is not the sender.
        {
            Env env(*this, features);
            Account const issuer{"credForeignIssuer"};
            Account const alice{"credForeignAlice"};
            Account const bob{"credForeignBob"};
            Account const carol{"credForeignCarol"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob, carol}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(811);
            auto const auditorEncryption = key(813);
            auto const aliceEncryption = key(815);
            auto const bobEncryption = key(817);

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
            env(fset(bob, asfDepositAuth));
            char const credentialType[] = "cred-foreign";
            env(deposit::authCredentials(bob, {{issuer, credentialType}}));
            env(credentials::create(carol, issuer, credentialType));
            env.close();
            env(credentials::accept(carol, issuer, credentialType));
            env.close();
            auto const carolCred =
                credentials::ledgerEntry(env, carol, issuer, credentialType);
            auto const carolCredId = carolCred[jss::result][jss::index].asString();

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
            env(send, credentials::Ids({carolCredId}), Ter(tecBAD_CREDENTIALS));
        }

        // Sec 8.3.2.2: Send requires confidential flag on the issuance.
        {
            Env env(*this, features);
            Account const issuer{"sndNoFlagIssuer"};
            Account const alice{"sndNoFlagAlice"};
            Account const bob{"sndNoFlagBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer});
            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            auto const r = scalar(11);
            auto const pk = key(821).publicKey;
            auto const ct = cm::encryptAmount(pk, 1, r);
            auto const commit = cm::pedersenCommit(1, r);
            if (!BEAST_EXPECT(ct && commit))
                return;
            send[sfSenderEncryptedAmount] = hex(*ct);
            send[sfDestinationEncryptedAmount] = hex(*ct);
            send[sfIssuerEncryptedAmount] = hex(*ct);
            send[sfAmountCommitment] = hex(*commit);
            send[sfBalanceCommitment] = hex(*commit);
            send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
            setConfidentialFee(send);
            env(send, Ter(tecNO_PERMISSION));
        }

        // Sec 8.3.2.2: confidential flag without IssuerEncryptionKey.
        {
            Env env(*this, features);
            Account const issuer{"sndNoKeyIssuer"};
            Account const alice{"sndNoKeyAlice"};
            Account const bob{"sndNoKeyBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            auto const r = scalar(13);
            auto const pk = key(823).publicKey;
            auto const ct = cm::encryptAmount(pk, 1, r);
            auto const commit = cm::pedersenCommit(1, r);
            if (!BEAST_EXPECT(ct && commit))
                return;
            send[sfSenderEncryptedAmount] = hex(*ct);
            send[sfDestinationEncryptedAmount] = hex(*ct);
            send[sfIssuerEncryptedAmount] = hex(*ct);
            send[sfAmountCommitment] = hex(*commit);
            send[sfBalanceCommitment] = hex(*commit);
            send[sfZKProof] = hex(std::array<std::uint8_t, 946>{});
            setConfidentialFee(send);
            env(send, Ter(tecNO_PERMISSION));
        }

        // Sec 7.3: Convert against a missing MPToken object.
        {
            Env env(*this, features);
            Account const issuer{"cvtNoMptIssuer"};
            Account const alice{"cvtNoMptAlice"};
            env.fund(XRP(10'000), alice);
            MPTTester mpt(env, issuer);
            mpt.create(
                {.maxAmt = 50,
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(825);
            auto const auditorEncryption = key(827);
            auto const aliceEncryption = key(829);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            setKeys[sfAuditorEncryptionKey] = hex(auditorEncryption.publicKey);
            env(setKeys);

            BEAST_EXPECT(!env.le(keylet::mptoken(issuanceID, alice.id())));
            env(convertTx(
                    alice,
                    issuanceID,
                    0,
                    aliceEncryption,
                    issuerEncryption,
                    auditorEncryption,
                    scalar(3),
                    env.seq(alice)),
                Ter(tecOBJECT_NOT_FOUND));
        }

        // Sec 10.3: ConvertBack missing issuance / auditor ciphertext forbidden.
        {
            Env env(*this, features);
            Account const issuer{"cbObjIssuer"};
            Account const alice{"cbObjAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(831);
            auto const aliceEncryption = key(833);
            auto const strayAuditor = key(835);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;
            BEAST_EXPECT(!aliceMpt->isFieldPresent(sfAuditorEncryptedBalance));

            std::uint64_t constexpr amount = 5;
            auto const withdrawRandomness = scalar(29);
            auto const withdrawBlinding = scalar(31);
            auto const holderWithdrawal =
                cm::encryptAmount(aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal =
                cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const auditorWithdrawal =
                cm::encryptAmount(strayAuditor.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(20, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(20 - amount, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
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
                .b = 20, .rho = withdrawBlinding, .sk = aliceEncryption.secret};
            auto const withdrawSigma = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(withdrawCtx));
            auto const withdrawRange = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment,
                20 - amount,
                withdrawBlinding,
                asSlice(withdrawCtx));
            if (!BEAST_EXPECT(withdrawSigma && withdrawRange))
                return;

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(makeMptID(1, alice));
            convertBack[sfMPTAmount] = std::to_string(amount);
            convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecOBJECT_NOT_FOUND));

            auto const withdrawCtx2 =
                convertBackContext(alice, issuanceID, env.seq(alice), aliceVersion);
            auto const withdrawSigma2 = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(withdrawCtx2));
            auto const withdrawRange2 = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment,
                20 - amount,
                withdrawBlinding,
                asSlice(withdrawCtx2));
            if (!BEAST_EXPECT(withdrawSigma2 && withdrawRange2))
                return;

            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfAuditorEncryptedAmount] = hex(*auditorWithdrawal);
            convertBack[sfZKProof] = joinedHex(*withdrawSigma2, *withdrawRange2);
            env(convertBack, Ter(tecNO_PERMISSION));
        }

        // Sec 7/8/10: auditor mirror present after Convert+Merge and mutates
        // across Send / ConvertBack.
        {
            Env env(*this, features);
            Account const issuer{"audMirrorIssuer"};
            Account const alice{"audMirrorAlice"};
            Account const bob{"audMirrorBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 30}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(841);
            auto const auditorEncryption = key(843);
            auto const aliceEncryption = key(845);
            auto const bobEncryption = key(847);

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

            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            auto bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(aliceMpt && bobMpt))
                return;
            BEAST_EXPECT(aliceMpt->isFieldPresent(sfAuditorEncryptedBalance));
            BEAST_EXPECT(bobMpt->isFieldPresent(sfAuditorEncryptedBalance));
            auto const aliceAuditorBefore = (*aliceMpt)[sfAuditorEncryptedBalance];
            auto const bobAuditorBefore = (*bobMpt)[sfAuditorEncryptedBalance];
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
            cm::SendPublicInput const sendInput{
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
            env(send);

            aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(aliceMpt && bobMpt))
                return;
            BEAST_EXPECT((*aliceMpt)[sfAuditorEncryptedBalance] != aliceAuditorBefore);
            BEAST_EXPECT((*bobMpt)[sfAuditorEncryptedBalance] != bobAuditorBefore);

            env(mergeTx(bob, issuanceID));
            bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMpt))
                return;
            auto const bobAuditorAfterMerge = (*bobMpt)[sfAuditorEncryptedBalance];
            auto const bobSpending =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceSpending]);
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
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(amount, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(0, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
                return;

            auto const bobVersion =
                (*bobMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const withdrawCtx =
                convertBackContext(bob, issuanceID, env.seq(bob), bobVersion);
            cm::ConvertBackPublicInput const withdrawInput{
                .holderKey = bobEncryption.publicKey,
                .balanceC1 = cm::ciphertextC1(*bobSpending),
                .balanceC2 = cm::ciphertextC2(*bobSpending),
                .balanceCommitment = *withdrawBalanceCommitment};
            cm::ConvertBackWitness const withdrawWitness{
                .b = amount, .rho = withdrawBlinding, .sk = bobEncryption.secret};
            auto const withdrawSigma = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(withdrawCtx));
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

            bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMpt))
                return;
            BEAST_EXPECT((*bobMpt)[sfAuditorEncryptedBalance] != bobAuditorAfterMerge);
        }
    }


    void
    testOneWayFlagEncZeroIssuanceAndConvertBackOAEvidence()
    {
        testcase(
            "requirement evidence: one-way confidential flag, EncZero IssuanceID "
            "domain substitution, ConvertBack OA unchanged (§10.5)");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 6.3.3: enable is one-way. Same-tx SetCanHold + IssuerEncryptionKey
        // succeeds; a later Set that only restates enable (no clear flag exists)
        // leaves lsfMPTCanHoldConfidentialBalance set.
        {
            Env env(*this, features);
            Account const issuer{"oneWayIssuer"};
            MPTTester mpt(env, issuer);
            mpt.create();
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(901);

            json::Value enable;
            enable[jss::TransactionType] = jss::MPTokenIssuanceSet;
            enable[sfAccount] = issuer.human();
            enable[sfMPTokenIssuanceID] = to_string(issuanceID);
            enable[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(enable, Txflags(tfMPTSetCanHoldConfidentialBalance));

            auto sle = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(sle))
                return;
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle->isFieldPresent(sfIssuerEncryptionKey));

            json::Value again;
            again[jss::TransactionType] = jss::MPTokenIssuanceSet;
            again[sfAccount] = issuer.human();
            again[sfMPTokenIssuanceID] = to_string(issuanceID);
            env(again, Txflags(tfMPTSetCanHoldConfidentialBalance));
            sle = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(sle))
                return;
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        // EncZero domain (SPEC INCONSISTENCY): XLS hashes Currency; this tree
        // substitutes MPTokenIssuanceID. Distinct issuances must therefore
        // yield distinct EncZero ciphertexts for the same account/issuer/key.
        {
            Account const issuer{"encZIssuer"};
            Account const alice{"encZAlice"};
            auto const pk = key(903).publicKey;
            MPTID const idA = makeMptID(1, issuer);
            MPTID const idB = makeMptID(2, issuer);
            BEAST_EXPECT(idA != idB);
            auto const zA1 =
                confidentialMPTEncryptedZero(pk, alice.id(), issuer.id(), idA);
            auto const zA2 =
                confidentialMPTEncryptedZero(pk, alice.id(), issuer.id(), idA);
            auto const zB =
                confidentialMPTEncryptedZero(pk, alice.id(), issuer.id(), idB);
            if (!BEAST_EXPECT(zA1 && zA2 && zB))
                return;
            BEAST_EXPECT(*zA1 == *zA2);
            BEAST_EXPECT(*zA1 != *zB);
        }

        // Sec 10.5 (not §10.7 narrative): ConvertBack reduces COA and restores
        // public MPTAmount; OutstandingAmount is unchanged.
        {
            Env env(*this, features);
            Account const issuer{"oaCbIssuer"};
            Account const alice{"oaCbAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(911);
            auto const auditorEncryption = key(913);
            auto const aliceEncryption = key(915);

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

            auto issuance = env.le(keylet::mptIssuance(issuanceID));
            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(issuance && aliceMpt))
                return;
            auto const oaBefore = (*issuance)[sfOutstandingAmount];
            auto const coaBefore =
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0);
            BEAST_EXPECT(oaBefore == 40);
            BEAST_EXPECT(coaBefore == 40);

            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 7;
            auto const withdrawRandomness = scalar(29);
            auto const withdrawBlinding = scalar(31);
            auto const holderWithdrawal = cm::encryptAmount(
                aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal = cm::encryptAmount(
                issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const auditorWithdrawal = cm::encryptAmount(
                auditorEncryption.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(40, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(40 - amount, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && auditorWithdrawal &&
                    withdrawBalanceCommitment && withdrawRemainderCommitment))
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
                .b = 40, .rho = withdrawBlinding, .sk = aliceEncryption.secret};
            auto const withdrawSigma = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(withdrawCtx));
            auto const withdrawRange = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment,
                40 - amount,
                withdrawBlinding,
                asSlice(withdrawCtx));
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
            env(convertBack);

            issuance = env.le(keylet::mptIssuance(issuanceID));
            aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(issuance && aliceMpt))
                return;
            // §10.5: OA unchanged; COA decreases; public MPTAmount restored.
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == oaBefore);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) ==
                coaBefore - amount);
            BEAST_EXPECT((*aliceMpt)[sfMPTAmount] == amount);
        }
    }


    void
    testNoAuditorSendAndMissingObjectEvidence()
    {
        testcase(
            "requirement evidence: Send without auditor (n=3), MergeInbox/"
            "Clawback missing objects, ConvertBack without confidential flag, "
            "subsequent Convert inbox credit");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        // Sec 8 / Updated §3: auditor-optional Send — three ciphertexts, OA/COA
        // unchanged, no auditor fields on MPToken.
        {
            Env env(*this, features);
            Account const issuer{"noAudOkIssuer"};
            Account const alice{"noAudOkAlice"};
            Account const bob{"noAudOkBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 20}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(921);
            auto const aliceEncryption = key(923);
            auto const bobEncryption = key(925);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTxIssuerOnly(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                scalar(5),
                env.seq(bob)));

            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            auto bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            auto issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(aliceMpt && bobMpt && issuance))
                return;
            BEAST_EXPECT(!aliceMpt->isFieldPresent(sfAuditorEncryptedBalance));
            BEAST_EXPECT(!bobMpt->isFieldPresent(sfAuditorEncryptedBalance));
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 20);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 20);

            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            auto const bobInboxBefore =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceInbox]);
            if (!BEAST_EXPECT(aliceSpending && bobInboxBefore))
                return;

            std::uint64_t constexpr amount = 6;
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
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount &&
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
                     issuerEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount)},
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
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            send[sfZKProof] = joinedHex(*sigma, *range);
            setConfidentialFee(send);
            env(send);

            issuance = env.le(keylet::mptIssuance(issuanceID));
            aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(issuance && aliceMpt && bobMpt))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 20);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 20);
            BEAST_EXPECT(!aliceMpt->isFieldPresent(sfAuditorEncryptedBalance));
            BEAST_EXPECT(!bobMpt->isFieldPresent(sfAuditorEncryptedBalance));
            auto const bobInboxAfter =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceInbox]);
            BEAST_EXPECT(bobInboxAfter && *bobInboxAfter != *bobInboxBefore);
            BEAST_EXPECT(
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0) ==
                aliceVersion + 1);
        }

        // Sec 9.2.1.2: MergeInbox missing issuance / missing MPToken.
        {
            Env env(*this, features);
            Account const issuer{"mergeMissIssuer"};
            Account const alice{"mergeMissAlice"};
            env.fund(XRP(10'000), alice);
            MPTTester mpt(env, issuer);
            mpt.create({.flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            env(mergeTx(alice, makeMptID(1, alice)), Ter(tecOBJECT_NOT_FOUND));
            env(mergeTx(alice, mpt.issuanceID()), Ter(tecOBJECT_NOT_FOUND));
        }

        // Sec 10.4.2.2: ConvertBack on an issuance without confidential flag.
        {
            Env env(*this, features);
            Account const issuer{"cbNoFlagIssuer"};
            Account const alice{"cbNoFlagAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 50,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 10}},
                 .flags = tfMPTCanTransfer});
            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(mpt.issuanceID());
            convertBack[sfMPTAmount] = "1";
            auto const r = scalar(3);
            auto const pk = key(931).publicKey;
            auto const ct = cm::encryptAmount(pk, 1, r);
            auto const commit = cm::pedersenCommit(1, r);
            if (!BEAST_EXPECT(ct && commit))
                return;
            convertBack[sfHolderEncryptedAmount] = hex(*ct);
            convertBack[sfIssuerEncryptedAmount] = hex(*ct);
            convertBack[sfBlindingFactor] = hex(r);
            convertBack[sfBalanceCommitment] = hex(*commit);
            convertBack[sfZKProof] = hex(std::array<std::uint8_t, 816>{});
            setConfidentialFee(convertBack);
            env(convertBack, Ter(tecNO_PERMISSION));
        }

        // Sec 11.3.2.2: Clawback against a holder with no MPToken.
        {
            Env env(*this, features);
            Account const issuer{"clawMissIssuer"};
            Account const alice{"clawMissAlice"};
            env.fund(XRP(10'000), alice);
            MPTTester mpt(env, issuer);
            mpt.create(
                {.flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(key(933).publicKey);
            env(setKeys);

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = alice.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = "1";
            clawback[sfZKProof] = hex(std::array<std::uint8_t, 64>{});
            setConfidentialFee(clawback);
            env(clawback, Ter(tecOBJECT_NOT_FOUND));
        }

        // Sec 7.5: subsequent Convert (no key) credits inbox and COA; OA unchanged.
        {
            Env env(*this, features);
            Account const issuer{"subCvtIssuer"};
            Account const alice{"subCvtAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 30}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(941);
            auto const auditorEncryption = key(943);
            auto const aliceEncryption = key(945);

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
            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            auto issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(aliceMpt && issuance))
                return;
            auto const inboxBefore =
                (*aliceMpt)[sfConfidentialBalanceInbox];
            auto const oaBefore = (*issuance)[sfOutstandingAmount];
            auto const coaBefore =
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0);
            auto const publicBefore = (*aliceMpt)[~sfMPTAmount].value_or(0);

            env(convertTxWithoutKey(
                alice,
                issuanceID,
                5,
                aliceEncryption,
                issuerEncryption,
                auditorEncryption,
                scalar(7)));

            aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            issuance = env.le(keylet::mptIssuance(issuanceID));
            if (!BEAST_EXPECT(aliceMpt && issuance))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == oaBefore);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) ==
                coaBefore + 5);
            BEAST_EXPECT((*aliceMpt)[~sfMPTAmount].value_or(0) == publicBefore - 5);
            BEAST_EXPECT((*aliceMpt)[sfConfidentialBalanceInbox] != inboxBefore);
        }
    }

    void
    testTicketContextBindingEvidence()
    {
        testcase(
            "requirement evidence: SequenceOrTicket transcript binding for "
            "Convert, Send, ConvertBack, and Clawback");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        Env env(*this, features);
        Account const issuer{"ticketIssuer"};
        Account const alice{"ticketAlice"};
        Account const bob{"ticketBob"};
        MPTTester mpt(env, issuer, {.holders = {alice, bob}});
        mpt.create(
            {.maxAmt = 100,
             .authorize = MPTCreate::allHolders,
             .pay = {{{alice}, 20}},
             .flags = tfMPTCanTransfer | tfMPTCanClawback |
                 tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();
        auto const issuerEncryption = key(951);
        auto const aliceEncryption = key(953);
        auto const bobEncryption = key(955);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        env(setKeys);

        // Updated §2.4: Convert key-registration PoK is bound to
        // SequenceOrTicket. A Sequence-bound proof fails through a Ticket;
        // rebuilding against the second Ticket succeeds.
        auto const convertTicket1 = env.seq(alice) + 1;
        auto const convertTicket2 = env.seq(alice) + 2;
        env(ticket::create(alice, 2));
        env.close();
        env(convertTxIssuerOnly(
                alice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                env.seq(alice)),
            ticket::Use(convertTicket1),
            Ter(tecBAD_PROOF));
        env(convertTxIssuerOnly(
                alice,
                issuanceID,
                20,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                convertTicket2),
            ticket::Use(convertTicket2));
        env(mergeTx(alice, issuanceID));
        env(convertTxIssuerOnly(
            bob,
            issuanceID,
            0,
            bobEncryption,
            issuerEncryption,
            scalar(5),
            env.seq(bob)));
        env.close();
        {
            auto const bobMpt0 = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMpt0))
                return;
            auto const bobSpend0 =
                cm::parseCiphertext((*bobMpt0)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(bobSpend0))
                return;
            // Convert initializes spending to domain EncZero and credits the
            // convert amount into the inbox (not spending).
            auto const encZero = confidentialMPTEncryptedZero(
                bobEncryption.publicKey, bob.id(), issuer.id(), issuanceID);
            auto const bobInbox0 =
                cm::parseCiphertext((*bobMpt0)[sfConfidentialBalanceInbox]);
            // creditField seeds a missing inbox as EncZero ⊕ delta, so the
            // convert(0) inbox is Enc(0, r_enczero+5), not Enc(0, scalar(5)).
            BEAST_EXPECT(encZero && bobSpend0 && *bobSpend0 == *encZero);
            BEAST_EXPECT(
                bobInbox0 &&
                ciphertextEncodes(*bobInbox0, bobEncryption.secret, 0));
        }

        auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(aliceMpt))
            return;
        auto const aliceSpending =
            cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(aliceSpending))
            return;

        std::uint64_t constexpr amount = 6;
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
        auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
        auto const balanceCommitment =
            cm::pedersenCommit(aliceBalance, balanceBlinding);
        auto const remainderCommitment =
            cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
        if (!BEAST_EXPECT(
                senderAmount && destinationAmount && issuerAmount &&
                amountCommitment && balanceCommitment && remainderCommitment))
            return;

        auto const aliceVersion =
            (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
        cm::SendPublicInput const sendInput{
            .recipientKeys =
                {aliceEncryption.publicKey,
                 bobEncryption.publicKey,
                 issuerEncryption.publicKey},
            .senderKey = aliceEncryption.publicKey,
            .c1 = cm::ciphertextC1(*senderAmount),
            .c2 =
                {cm::ciphertextC2(*senderAmount),
                 cm::ciphertextC2(*destinationAmount),
                 cm::ciphertextC2(*issuerAmount)},
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
        json::Value send;
        send[jss::TransactionType] = jss::ConfidentialMPTSend;
        send[sfAccount] = alice.human();
        send[sfDestination] = bob.human();
        send[sfMPTokenIssuanceID] = to_string(issuanceID);
        send[sfSenderEncryptedAmount] = hex(*senderAmount);
        send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
        send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        send[sfAmountCommitment] = hex(*amountCommitment);
        send[sfBalanceCommitment] = hex(*balanceCommitment);
        setConfidentialFee(send);

        auto const setProof = [&](std::uint32_t sequenceOrTicket) {
            auto const context =
                sendContext(alice, issuanceID, sequenceOrTicket, bob, aliceVersion);
            auto const sigma =
                cm::proveSendSigma(sendInput, sendWitness, asSlice(context));
            auto const range = cm::proveAggregatedBulletproof(
                *amountCommitment,
                *remainderCommitment,
                amount,
                sendRandomness,
                aliceBalance - amount,
                remainderBlinding,
                asSlice(context));
            if (!sigma || !range)
                Throw<std::runtime_error>("Unable to create ticket-bound Send proof");
            send[sfZKProof] = joinedHex(*sigma, *range);
        };

        // Updated §3.7: Send uses the same SequenceOrTicket binding.
        auto const sendTicket1 = env.seq(alice) + 1;
        auto const sendTicket2 = env.seq(alice) + 2;
        env(ticket::create(alice, 2));
        env.close();
        setProof(env.seq(alice));
        env(send, ticket::Use(sendTicket1), Ter(tecBAD_PROOF));
        setProof(sendTicket2);
        env(send, ticket::Use(sendTicket2));
        env.require(tickets(alice, 0));
        // Commit the ticketed Send before the next transaction phase.
        env.close();

        // Updated §4.7: ConvertBack proof also binds SequenceOrTicket.
        env(mergeTx(bob, issuanceID));
        auto bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
        if (!BEAST_EXPECT(bobMpt))
            return;
        auto const bobSpending =
            cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(bobSpending))
            return;
        // After Send(6)+Merge, spending must encrypt 6.
        BEAST_EXPECT(
            ciphertextEncodes(*bobSpending, bobEncryption.secret, amount));
        auto const withdrawRandomness = scalar(29);
        auto const withdrawBlinding = scalar(31);
        auto const holderWithdrawal =
            cm::encryptAmount(bobEncryption.publicKey, amount, withdrawRandomness);
        auto const issuerWithdrawal =
            cm::encryptAmount(issuerEncryption.publicKey, amount, withdrawRandomness);
        auto const withdrawBalanceCommitment =
            cm::pedersenCommit(amount, withdrawBlinding);
        auto const withdrawRemainderCommitment =
            cm::pedersenCommit(0, withdrawBlinding);
        if (!BEAST_EXPECT(
                holderWithdrawal && issuerWithdrawal &&
                withdrawBalanceCommitment && withdrawRemainderCommitment))
            return;

        auto const bobVersion =
            (*bobMpt)[~sfConfidentialBalanceVersion].value_or(0);
        cm::ConvertBackPublicInput const withdrawInput{
            .holderKey = bobEncryption.publicKey,
            .balanceC1 = cm::ciphertextC1(*bobSpending),
            .balanceC2 = cm::ciphertextC2(*bobSpending),
            .balanceCommitment = *withdrawBalanceCommitment};
        cm::ConvertBackWitness const withdrawWitness{
            .b = amount, .rho = withdrawBlinding, .sk = bobEncryption.secret};
        json::Value convertBack;
        convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        convertBack[sfAccount] = bob.human();
        convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
        convertBack[sfMPTAmount] = std::to_string(amount);
        convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
        convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
        convertBack[sfBlindingFactor] = hex(withdrawRandomness);
        convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
        setConfidentialFee(convertBack);
        auto const setConvertBackProof = [&](std::uint32_t sequenceOrTicket) {
            auto const context =
                convertBackContext(bob, issuanceID, sequenceOrTicket, bobVersion);
            auto const sigma = cm::proveConvertBackSigma(
                withdrawInput, withdrawWitness, asSlice(context));
            auto const range = cm::proveSingleBulletproof(
                *withdrawRemainderCommitment, 0, withdrawBlinding, asSlice(context));
            if (!sigma || !range)
                Throw<std::runtime_error>(
                    "Unable to create ticket-bound ConvertBack proof");
            convertBack[sfZKProof] = joinedHex(*sigma, *range);
        };

        auto const convertBackTicket1 = env.seq(bob) + 1;
        auto const convertBackTicket2 = env.seq(bob) + 2;
        env(ticket::create(bob, 2));
        env.close();
        setConvertBackProof(env.seq(bob));
        env(
            convertBack,
            ticket::Use(convertBackTicket1),
            Ter(tecBAD_PROOF));
        setConvertBackProof(convertBackTicket2);
        env(convertBack, ticket::Use(convertBackTicket2));
        env.require(tickets(bob, 0));

        // Updated §5.6: Clawback intentionally omits CBS version, but still
        // binds the issuer's SequenceOrTicket in TransactionContextID.
        auto const aliceAfterSend =
            env.le(keylet::mptoken(issuanceID, alice.id()));
        if (!BEAST_EXPECT(aliceAfterSend))
            return;
        auto const aliceIssuerBalance =
            cm::parseCiphertext((*aliceAfterSend)[sfIssuerEncryptedBalance]);
        if (!BEAST_EXPECT(aliceIssuerBalance))
            return;
        std::uint64_t constexpr clawAmount = aliceBalance - amount;
        cm::ClawbackPublicInput const clawInput{
            .issuerKey = issuerEncryption.publicKey,
            .c1 = cm::ciphertextC1(*aliceIssuerBalance),
            .c2 = cm::ciphertextC2(*aliceIssuerBalance),
            .m = clawAmount};
        json::Value clawback;
        clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
        clawback[sfAccount] = issuer.human();
        clawback[sfHolder] = alice.human();
        clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
        clawback[sfMPTAmount] = std::to_string(clawAmount);
        setConfidentialFee(clawback);
        auto const setClawbackProof = [&](std::uint32_t sequenceOrTicket) {
            auto const context =
                clawbackContext(issuer, issuanceID, sequenceOrTicket, alice);
            auto const proof = cm::proveClawback(
                clawInput, issuerEncryption.secret, asSlice(context));
            if (!proof)
                Throw<std::runtime_error>(
                    "Unable to create ticket-bound Clawback proof");
            clawback[sfZKProof] = hex(*proof);
        };

        auto const clawbackTicket1 = env.seq(issuer) + 1;
        auto const clawbackTicket2 = env.seq(issuer) + 2;
        env(ticket::create(issuer, 2));
        env.close();
        setClawbackProof(env.seq(issuer));
        env(clawback, ticket::Use(clawbackTicket1), Ter(tecBAD_PROOF));
        setClawbackProof(clawbackTicket2);
        env(clawback, ticket::Use(clawbackTicket2));
        env.require(tickets(issuer, 0));
    }


    void
    testDedicatedVaultSection107NarrativeEvidence()
    {
        // XLS-0096 §10.7 walkthrough (dedicated vault) with §10.5 accounting:
        // Convert 50 → Send 20 → ConvertBack 30. Observers learn net confidential
        // supply change 50-30=20, not the hidden Send amount. §10.7's prose that
        // ConvertBack decreases OutstandingAmount is a SPEC INCONSISTENCY with
        // §10.5; this tree follows §10.5 (OA unchanged, COA decreases).
        testcase(
            "requirement evidence: §10.7 dedicated-vault Convert/Send/ConvertBack "
            "accounting under §10.5 OA rules");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);

        Env env(*this, features);
        Account const issuer{"vault107Issuer"};
        Account const vault{"vault107"};
        Account const bob{"vault107Bob"};
        MPTTester mpt(env, issuer, {.holders = {vault, bob}});
        mpt.create(
            {.maxAmt = 200,
             .authorize = MPTCreate::allHolders,
             .pay = {{{vault}, 50}},
             .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
        auto const issuanceID = mpt.issuanceID();
        auto const issuerEncryption = key(1101);
        auto const vaultEncryption = key(1103);
        auto const bobEncryption = key(1105);

        json::Value setKeys;
        setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
        setKeys[sfAccount] = issuer.human();
        setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
        setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
        env(setKeys);

        // Issuer account cannot convert its own issuance (dedicated-account model).
        env(convertTxIssuerOnly(
                issuer,
                issuanceID,
                1,
                vaultEncryption,
                issuerEncryption,
                scalar(1),
                env.seq(issuer)),
            Ter(temMALFORMED));

        // Step 1: dedicated vault converts 50 public → confidential.
        env(convertTxIssuerOnly(
            vault,
            issuanceID,
            50,
            vaultEncryption,
            issuerEncryption,
            scalar(7),
            env.seq(vault)));
        env(mergeTx(vault, issuanceID));
        env(convertTxIssuerOnly(
            bob,
            issuanceID,
            0,
            bobEncryption,
            issuerEncryption,
            scalar(9),
            env.seq(bob)));

        auto issuance = env.le(keylet::mptIssuance(issuanceID));
        auto vaultMpt = env.le(keylet::mptoken(issuanceID, vault.id()));
        if (!BEAST_EXPECT(issuance && vaultMpt))
            return;
        BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 50);
        BEAST_EXPECT((*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 50);
        BEAST_EXPECT((*vaultMpt)[~sfMPTAmount].value_or(0) == 0);

        auto const vaultSpending =
            cm::parseCiphertext((*vaultMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(vaultSpending))
            return;

        // Step 2: confidential Send of 20 (amount hidden) vault → bob.
        std::uint64_t constexpr sendAmount = 20;
        std::uint64_t constexpr vaultBalance = 50;
        auto const sendRandomness = scalar(41);
        auto const balanceBlinding = scalar(43);
        auto const remainderBlinding = scalar(2);
        auto const senderAmount =
            cm::encryptAmount(vaultEncryption.publicKey, sendAmount, sendRandomness);
        auto const destinationAmount =
            cm::encryptAmount(bobEncryption.publicKey, sendAmount, sendRandomness);
        auto const issuerAmount =
            cm::encryptAmount(issuerEncryption.publicKey, sendAmount, sendRandomness);
        auto const amountCommitment = cm::pedersenCommit(sendAmount, sendRandomness);
        auto const balanceCommitment =
            cm::pedersenCommit(vaultBalance, balanceBlinding);
        auto const remainderCommitment =
            cm::pedersenCommit(vaultBalance - sendAmount, remainderBlinding);
        if (!BEAST_EXPECT(
                senderAmount && destinationAmount && issuerAmount && amountCommitment &&
                balanceCommitment && remainderCommitment))
            return;

        auto const vaultVersion =
            (*vaultMpt)[~sfConfidentialBalanceVersion].value_or(0);
        auto const sendCtx =
            sendContext(vault, issuanceID, env.seq(vault), bob, vaultVersion);
        cm::SendPublicInput sendInput{
            .recipientKeys =
                {vaultEncryption.publicKey,
                 bobEncryption.publicKey,
                 issuerEncryption.publicKey},
            .senderKey = vaultEncryption.publicKey,
            .c1 = cm::ciphertextC1(*senderAmount),
            .c2 =
                {cm::ciphertextC2(*senderAmount),
                 cm::ciphertextC2(*destinationAmount),
                 cm::ciphertextC2(*issuerAmount)},
            .amountCommitment = *amountCommitment,
            .balanceCommitment = *balanceCommitment,
            .balanceC1 = cm::ciphertextC1(*vaultSpending),
            .balanceC2 = cm::ciphertextC2(*vaultSpending)};
        cm::SendWitness const sendWitness{
            .m = sendAmount,
            .r = sendRandomness,
            .b = vaultBalance,
            .rho = balanceBlinding,
            .sk = vaultEncryption.secret};
        auto const sigma = cm::proveSendSigma(sendInput, sendWitness, asSlice(sendCtx));
        auto const range = cm::proveAggregatedBulletproof(
            *amountCommitment,
            *remainderCommitment,
            sendAmount,
            sendRandomness,
            vaultBalance - sendAmount,
            remainderBlinding,
            asSlice(sendCtx));
        if (!BEAST_EXPECT(sigma && range))
            return;

        json::Value send;
        send[jss::TransactionType] = jss::ConfidentialMPTSend;
        send[sfAccount] = vault.human();
        send[sfDestination] = bob.human();
        send[sfMPTokenIssuanceID] = to_string(issuanceID);
        send[sfSenderEncryptedAmount] = hex(*senderAmount);
        send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
        send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
        send[sfAmountCommitment] = hex(*amountCommitment);
        send[sfBalanceCommitment] = hex(*balanceCommitment);
        send[sfZKProof] = joinedHex(*sigma, *range);
        setConfidentialFee(send);
        env(send);

        issuance = env.le(keylet::mptIssuance(issuanceID));
        if (!BEAST_EXPECT(issuance))
            return;
        // Send redistributes confidential value: OA and COA unchanged.
        BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 50);
        BEAST_EXPECT((*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 50);

        env(mergeTx(bob, issuanceID));

        // Step 3: ConvertBack 30 from the dedicated vault.
        vaultMpt = env.le(keylet::mptoken(issuanceID, vault.id()));
        if (!BEAST_EXPECT(vaultMpt))
            return;
        auto const vaultSpendingAfterSend =
            cm::parseCiphertext((*vaultMpt)[sfConfidentialBalanceSpending]);
        if (!BEAST_EXPECT(vaultSpendingAfterSend))
            return;

        std::uint64_t constexpr convertBackAmount = 30;
        std::uint64_t constexpr vaultBalanceAfterSend = vaultBalance - sendAmount;
        auto const withdrawRandomness = scalar(29);
        auto const withdrawBlinding = scalar(31);
        auto const holderWithdrawal = cm::encryptAmount(
            vaultEncryption.publicKey, convertBackAmount, withdrawRandomness);
        auto const issuerWithdrawal = cm::encryptAmount(
            issuerEncryption.publicKey, convertBackAmount, withdrawRandomness);
        auto const withdrawBalanceCommitment =
            cm::pedersenCommit(vaultBalanceAfterSend, withdrawBlinding);
        auto const withdrawRemainderCommitment = cm::pedersenCommit(
            vaultBalanceAfterSend - convertBackAmount, withdrawBlinding);
        if (!BEAST_EXPECT(
                holderWithdrawal && issuerWithdrawal && withdrawBalanceCommitment &&
                withdrawRemainderCommitment))
            return;

        auto const vaultVersion2 =
            (*vaultMpt)[~sfConfidentialBalanceVersion].value_or(0);
        auto const withdrawCtx =
            convertBackContext(vault, issuanceID, env.seq(vault), vaultVersion2);
        cm::ConvertBackPublicInput const withdrawInput{
            .holderKey = vaultEncryption.publicKey,
            .balanceC1 = cm::ciphertextC1(*vaultSpendingAfterSend),
            .balanceC2 = cm::ciphertextC2(*vaultSpendingAfterSend),
            .balanceCommitment = *withdrawBalanceCommitment};
        cm::ConvertBackWitness const withdrawWitness{
            .b = vaultBalanceAfterSend,
            .rho = withdrawBlinding,
            .sk = vaultEncryption.secret};
        auto const withdrawSigma = cm::proveConvertBackSigma(
            withdrawInput, withdrawWitness, asSlice(withdrawCtx));
        auto const withdrawRange = cm::proveSingleBulletproof(
            *withdrawRemainderCommitment,
            vaultBalanceAfterSend - convertBackAmount,
            withdrawBlinding,
            asSlice(withdrawCtx));
        if (!BEAST_EXPECT(withdrawSigma && withdrawRange))
            return;

        json::Value convertBack;
        convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        convertBack[sfAccount] = vault.human();
        convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
        convertBack[sfMPTAmount] = std::to_string(convertBackAmount);
        convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
        convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
        convertBack[sfBlindingFactor] = hex(withdrawRandomness);
        convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
        convertBack[sfZKProof] = joinedHex(*withdrawSigma, *withdrawRange);
        setConfidentialFee(convertBack);
        env(convertBack);

        issuance = env.le(keylet::mptIssuance(issuanceID));
        vaultMpt = env.le(keylet::mptoken(issuanceID, vault.id()));
        if (!BEAST_EXPECT(issuance && vaultMpt))
            return;
        // §10.5 (over §10.7 narrative): OA unchanged; COA = 50 - 30 = 20;
        // vault public MPTAmount restored by 30. Net confidential supply 20
        // remains (bob holds the hidden Send), matching §10.7.1 inference.
        BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 50);
        BEAST_EXPECT((*issuance)[~sfConfidentialOutstandingAmount].value_or(0) == 20);
        BEAST_EXPECT((*vaultMpt)[sfMPTAmount] == convertBackAmount);
    }


    void
    testSplitProofFailureAndClawbackPendingInboxEvidence()
    {
        // XLS-0096 §8.3.2.5 / §10.4.2.7-8: sigma and Bulletproof are independent
        // failure gates. Corrupt each half of an otherwise-valid ZKProof and
        // expect tecBAD_PROOF; an intact proof then succeeds. Also cover §11.4
        // clawback when the holder still has a non-zero confidential inbox.
        testcase(
            "requirement evidence: independent sigma/Bulletproof failures and "
            "delegated clawback with pending inbox");
        using namespace test::jtx;

        auto features = testableAmendments();
        features.set(featureConfidentialTransfer);
        features.set(featureDynamicMPT);
        features.set(featurePermissionDelegationV1_1);

        auto const corruptByte = [](std::string hexStr, std::size_t byteIndex) {
            auto const i = byteIndex * 2;
            if (i >= hexStr.size())
                Throw<std::runtime_error>("corruptByte out of range");
            hexStr[i] = (hexStr[i] == '0') ? '1' : '0';
            return hexStr;
        };

        // --- Send: corrupt sigma half, then Bulletproof half, then succeed ---
        {
            Env env(*this, features);
            Account const issuer{"splitSendIssuer"};
            Account const alice{"splitSendAlice"};
            Account const bob{"splitSendBob"};
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 40}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(1201);
            auto const aliceEncryption = key(1203);
            auto const bobEncryption = key(1205);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                40,
                aliceEncryption,
                issuerEncryption,
                scalar(3),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTxIssuerOnly(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                scalar(5),
                env.seq(bob)));

            auto const aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 7;
            std::uint64_t constexpr aliceBalance = 40;
            auto const sendRandomness = scalar(41);
            auto const balanceBlinding = scalar(43);
            auto const remainderBlinding = scalar(2);
            auto const senderAmount =
                cm::encryptAmount(aliceEncryption.publicKey, amount, sendRandomness);
            auto const destinationAmount =
                cm::encryptAmount(bobEncryption.publicKey, amount, sendRandomness);
            auto const issuerAmount =
                cm::encryptAmount(issuerEncryption.publicKey, amount, sendRandomness);
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            cm::SendPublicInput const sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     bobEncryption.publicKey,
                     issuerEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount)},
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

            json::Value send;
            send[jss::TransactionType] = jss::ConfidentialMPTSend;
            send[sfAccount] = alice.human();
            send[sfDestination] = bob.human();
            send[sfMPTokenIssuanceID] = to_string(issuanceID);
            send[sfSenderEncryptedAmount] = hex(*senderAmount);
            send[sfDestinationEncryptedAmount] = hex(*destinationAmount);
            send[sfIssuerEncryptedAmount] = hex(*issuerAmount);
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            setConfidentialFee(send);

            auto const setProof = [&](std::uint32_t sequenceOrTicket) {
                auto const context =
                    sendContext(alice, issuanceID, sequenceOrTicket, bob, aliceVersion);
                auto const sigma =
                    cm::proveSendSigma(sendInput, sendWitness, asSlice(context));
                auto const range = cm::proveAggregatedBulletproof(
                    *amountCommitment,
                    *remainderCommitment,
                    amount,
                    sendRandomness,
                    aliceBalance - amount,
                    remainderBlinding,
                    asSlice(context));
                if (!sigma || !range)
                    Throw<std::runtime_error>("Unable to create Send split-proof");
                return joinedHex(*sigma, *range);
            };

            auto proof = setProof(env.seq(alice));
            send[sfZKProof] = corruptByte(proof, 0);
            env(send, Ter(tecBAD_PROOF));

            proof = setProof(env.seq(alice));
            send[sfZKProof] = corruptByte(proof, cm::kSendSigmaBytes);
            env(send, Ter(tecBAD_PROOF));

            send[sfZKProof] = setProof(env.seq(alice));
            env(send);
        }

        // --- ConvertBack: same independent sigma / Bulletproof gates ---
        {
            Env env(*this, features);
            Account const issuer{"splitCbIssuer"};
            Account const alice{"splitCbAlice"};
            MPTTester mpt(env, issuer, {.holders = {alice}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 25}},
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(1211);
            auto const aliceEncryption = key(1213);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                25,
                aliceEncryption,
                issuerEncryption,
                scalar(11),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));

            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 9;
            std::uint64_t constexpr aliceBalance = 25;
            auto const withdrawRandomness = scalar(29);
            auto const withdrawBlinding = scalar(31);
            auto const holderWithdrawal = cm::encryptAmount(
                aliceEncryption.publicKey, amount, withdrawRandomness);
            auto const issuerWithdrawal = cm::encryptAmount(
                issuerEncryption.publicKey, amount, withdrawRandomness);
            auto const withdrawBalanceCommitment =
                cm::pedersenCommit(aliceBalance, withdrawBlinding);
            auto const withdrawRemainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, withdrawBlinding);
            if (!BEAST_EXPECT(
                    holderWithdrawal && issuerWithdrawal && withdrawBalanceCommitment &&
                    withdrawRemainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            cm::ConvertBackPublicInput const withdrawInput{
                .holderKey = aliceEncryption.publicKey,
                .balanceC1 = cm::ciphertextC1(*aliceSpending),
                .balanceC2 = cm::ciphertextC2(*aliceSpending),
                .balanceCommitment = *withdrawBalanceCommitment};
            cm::ConvertBackWitness const withdrawWitness{
                .b = aliceBalance,
                .rho = withdrawBlinding,
                .sk = aliceEncryption.secret};

            json::Value convertBack;
            convertBack[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
            convertBack[sfAccount] = alice.human();
            convertBack[sfMPTokenIssuanceID] = to_string(issuanceID);
            convertBack[sfMPTAmount] = std::to_string(amount);
            convertBack[sfHolderEncryptedAmount] = hex(*holderWithdrawal);
            convertBack[sfIssuerEncryptedAmount] = hex(*issuerWithdrawal);
            convertBack[sfBlindingFactor] = hex(withdrawRandomness);
            convertBack[sfBalanceCommitment] = hex(*withdrawBalanceCommitment);
            setConfidentialFee(convertBack);

            auto const setProof = [&](std::uint32_t sequenceOrTicket) {
                auto const context = convertBackContext(
                    alice, issuanceID, sequenceOrTicket, aliceVersion);
                auto const sigma = cm::proveConvertBackSigma(
                    withdrawInput, withdrawWitness, asSlice(context));
                auto const range = cm::proveSingleBulletproof(
                    *withdrawRemainderCommitment,
                    aliceBalance - amount,
                    withdrawBlinding,
                    asSlice(context));
                if (!sigma || !range)
                    Throw<std::runtime_error>(
                        "Unable to create ConvertBack split-proof");
                return joinedHex(*sigma, *range);
            };

            auto proof = setProof(env.seq(alice));
            convertBack[sfZKProof] = corruptByte(proof, 0);
            env(convertBack, Ter(tecBAD_PROOF));

            proof = setProof(env.seq(alice));
            convertBack[sfZKProof] =
                corruptByte(proof, cm::kConvertBackSigmaBytes);
            env(convertBack, Ter(tecBAD_PROOF));

            convertBack[sfZKProof] = setProof(env.seq(alice));
            env(convertBack);

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(issuance && aliceMpt))
                return;
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == 25);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) ==
                aliceBalance - amount);
            BEAST_EXPECT((*aliceMpt)[sfMPTAmount] == amount);
        }

        // --- Delegated Clawback while destination holds unmerged inbox funds ---
        {
            Env env(*this, features);
            Account const issuer{"inboxClawIssuer"};
            Account const alice{"inboxClawAlice"};
            Account const bob{"inboxClawBob"};
            Account const delegate{"inboxClawDelegate"};
            env.fund(XRP(10'000), delegate);
            MPTTester mpt(env, issuer, {.holders = {alice, bob}});
            mpt.create(
                {.maxAmt = 100,
                 .authorize = MPTCreate::allHolders,
                 .pay = {{{alice}, 30}},
                 .flags = tfMPTCanTransfer | tfMPTCanClawback |
                     tfMPTCanHoldConfidentialBalance});
            auto const issuanceID = mpt.issuanceID();
            auto const issuerEncryption = key(1221);
            auto const aliceEncryption = key(1223);
            auto const bobEncryption = key(1225);

            json::Value setKeys;
            setKeys[jss::TransactionType] = jss::MPTokenIssuanceSet;
            setKeys[sfAccount] = issuer.human();
            setKeys[sfMPTokenIssuanceID] = to_string(issuanceID);
            setKeys[sfIssuerEncryptionKey] = hex(issuerEncryption.publicKey);
            env(setKeys);

            env(convertTxIssuerOnly(
                alice,
                issuanceID,
                30,
                aliceEncryption,
                issuerEncryption,
                scalar(13),
                env.seq(alice)));
            env(mergeTx(alice, issuanceID));
            env(convertTxIssuerOnly(
                bob,
                issuanceID,
                0,
                bobEncryption,
                issuerEncryption,
                scalar(15),
                env.seq(bob)));

            auto aliceMpt = env.le(keylet::mptoken(issuanceID, alice.id()));
            if (!BEAST_EXPECT(aliceMpt))
                return;
            auto const aliceSpending =
                cm::parseCiphertext((*aliceMpt)[sfConfidentialBalanceSpending]);
            if (!BEAST_EXPECT(aliceSpending))
                return;

            std::uint64_t constexpr amount = 10;
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
            auto const amountCommitment = cm::pedersenCommit(amount, sendRandomness);
            auto const balanceCommitment =
                cm::pedersenCommit(aliceBalance, balanceBlinding);
            auto const remainderCommitment =
                cm::pedersenCommit(aliceBalance - amount, remainderBlinding);
            if (!BEAST_EXPECT(
                    senderAmount && destinationAmount && issuerAmount &&
                    amountCommitment && balanceCommitment && remainderCommitment))
                return;

            auto const aliceVersion =
                (*aliceMpt)[~sfConfidentialBalanceVersion].value_or(0);
            auto const sendCtx =
                sendContext(alice, issuanceID, env.seq(alice), bob, aliceVersion);
            cm::SendPublicInput const sendInput{
                .recipientKeys =
                    {aliceEncryption.publicKey,
                     bobEncryption.publicKey,
                     issuerEncryption.publicKey},
                .senderKey = aliceEncryption.publicKey,
                .c1 = cm::ciphertextC1(*senderAmount),
                .c2 =
                    {cm::ciphertextC2(*senderAmount),
                     cm::ciphertextC2(*destinationAmount),
                     cm::ciphertextC2(*issuerAmount)},
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
            send[sfAmountCommitment] = hex(*amountCommitment);
            send[sfBalanceCommitment] = hex(*balanceCommitment);
            send[sfZKProof] = joinedHex(*sigma, *range);
            setConfidentialFee(send);
            env(send);
            // Intentionally leave bob's inbox unmerged.

            auto bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(bobMpt))
                return;
            auto const bobInbox =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceInbox]);
            auto const expectedZero = confidentialMPTEncryptedZero(
                bobEncryption.publicKey, bob.id(), issuer.id(), issuanceID);
            if (!BEAST_EXPECT(bobInbox && expectedZero))
                return;
            BEAST_EXPECT(*bobInbox != *expectedZero);

            auto const bobIssuer =
                cm::parseCiphertext((*bobMpt)[sfIssuerEncryptedBalance]);
            if (!BEAST_EXPECT(bobIssuer))
                return;

            cm::ClawbackPublicInput const clawInput{
                .issuerKey = issuerEncryption.publicKey,
                .c1 = cm::ciphertextC1(*bobIssuer),
                .c2 = cm::ciphertextC2(*bobIssuer),
                .m = amount};

            json::Value clawback;
            clawback[jss::TransactionType] = jss::ConfidentialMPTClawback;
            clawback[sfAccount] = issuer.human();
            clawback[sfHolder] = bob.human();
            clawback[sfMPTokenIssuanceID] = to_string(issuanceID);
            clawback[sfMPTAmount] = std::to_string(amount);
            setConfidentialFee(clawback);

            // XLS-0096 §5.5: a delegate may act for the issuer, but only after
            // receiving the transaction permission. Account remains the issuer;
            // Delegate identifies and signs/pays as the authorized account.
            auto makeClawProof = [&](std::uint32_t sequenceOrTicket) {
                auto const context =
                    clawbackContext(issuer, issuanceID, sequenceOrTicket, bob);
                auto const proof = cm::proveClawback(
                    clawInput, issuerEncryption.secret, asSlice(context));
                if (!proof)
                    Throw<std::runtime_error>(
                        "Unable to create delegated Clawback proof");
                return *proof;
            };

            clawback[sfZKProof] = hex(makeClawProof(env.seq(issuer)));
            env(
                clawback,
                delegate::As(delegate),
                Ter(terNO_DELEGATE_PERMISSION));

            env(delegate::set(
                issuer, delegate, {"ConfidentialMPTClawback"}));
            env.close();
            clawback[sfZKProof] = hex(makeClawProof(env.seq(issuer)));
            env(clawback, delegate::As(delegate));

            auto const issuance = env.le(keylet::mptIssuance(issuanceID));
            bobMpt = env.le(keylet::mptoken(issuanceID, bob.id()));
            if (!BEAST_EXPECT(issuance && bobMpt))
                return;
            // §11.4: clawback burns OA+COA by the revealed amount and resets
            // spending, inbox, and issuer mirror to EncZero — even when value
            // still sat only in the inbox.
            BEAST_EXPECT((*issuance)[sfOutstandingAmount] == aliceBalance - amount);
            BEAST_EXPECT(
                (*issuance)[~sfConfidentialOutstandingAmount].value_or(0) ==
                aliceBalance - amount);
            auto const bobInboxAfter =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceInbox]);
            auto const bobSpendingAfter =
                cm::parseCiphertext((*bobMpt)[sfConfidentialBalanceSpending]);
            auto const bobIssuerAfter =
                cm::parseCiphertext((*bobMpt)[sfIssuerEncryptedBalance]);
            auto const zeroHolder = confidentialMPTEncryptedZero(
                bobEncryption.publicKey, bob.id(), issuer.id(), issuanceID);
            auto const zeroIssuer = confidentialMPTEncryptedZero(
                issuerEncryption.publicKey, bob.id(), issuer.id(), issuanceID);
            if (!BEAST_EXPECT(
                    bobInboxAfter && bobSpendingAfter && bobIssuerAfter && zeroHolder &&
                    zeroIssuer))
                return;
            BEAST_EXPECT(*bobInboxAfter == *zeroHolder);
            BEAST_EXPECT(*bobSpendingAfter == *zeroHolder);
            BEAST_EXPECT(*bobIssuerAfter == *zeroIssuer);
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
        testPreclaimCoverageMatrix();
        testLifecycleGateEvidence();
        testCredentialObjectMirrorEvidence();
        testOneWayFlagEncZeroIssuanceAndConvertBackOAEvidence();
        testNoAuditorSendAndMissingObjectEvidence();
        testTicketContextBindingEvidence();
        testDedicatedVaultSection107NarrativeEvidence();
        testSplitProofFailureAndClawbackPendingInboxEvidence();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTFlow, app, xrpl);

}  // namespace xrpl
