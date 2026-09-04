//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2026 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <test/jtx.h>
#include <test/jtx/delegate.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/Serializer.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/detail/STVar.h>

#include <cstdint>
#include <string>

namespace xrpl {
namespace test {

class ConfidentialMPTIssuance_test : public beast::unit_test::Suite
{
    // secp256k1 G and 2G (compressed) — valid 33-byte points.
    static constexpr char const* kKeyG =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    static constexpr char const* kKey2G =
        "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
    // 33 bytes with 0x02 prefix, but not on the curve.
    static constexpr char const* kKeyInvalidPoint =
        "020000000000000000000000000000000000000000000000000000000000000000";
    // Wrong length.
    static constexpr char const* kKeyShort = "0279BE667EF9DCBBAC55A06295CE870B";

    FeatureBitset
    withConfidential()
    {
        return jtx::testableAmendments() | featureConfidentialTransfer;
    }

    FeatureBitset
    withoutConfidential()
    {
        return jtx::testableAmendments() - featureConfidentialTransfer;
    }

    void
    testAmendmentDisabled()
    {
        testcase("amendment disabled");
        using namespace jtx;

        Env env{*this, withoutConfidential()};
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();

        BEAST_EXPECT(!env.current()->rules().enabled(featureConfidentialTransfer));

        MPTTester mpt(env, alice, {.fund = false});
        mpt.create({.flags = tfMPTCanHoldConfidentialBalance, .err = temDISABLED});

        mpt.create({});
        mpt.set(
            {.flags = tfMPTSetCanHoldConfidentialBalance,
             .issuerEncryptionKey = kKeyG,
             .err = temDISABLED});

        // Fresh tester — prior create already owns an issuance on alice.
        MPTTester mpt2(env, alice, {.fund = false});
        mpt2.create({.immutableFlags = lsifMPTCanHoldConfidentialBalance, .err = temDISABLED});
    }

    void
    testCreateConfidential()
    {
        testcase("create confidential flag and immutable lock");
        using namespace jtx;

        // Create with confidential flag, no transfer fee.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            // SoeDefault: absent COA reads as 0.
            BEAST_EXPECT((*sle)[sfConfidentialOutstandingAmount] == 0);
            BEAST_EXPECT(!sle->isFieldPresent(sfIssuerEncryptionKey));
        }

        // Create confidential + transfer fee → temBAD_TRANSFER_FEE.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.transferFee = 100,
                 .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer,
                 .err = temBAD_TRANSFER_FEE});
        }

        // Create with lsif set (lsf unset) — permanently blocks later enable.
        // Spec §6.3.1: Create with lsif set and lsf unset permanently blocks
        // enabling confidentiality via Set.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .immutableFlags = lsifMPTCanHoldConfidentialBalance});
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(!sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(
                ((*sle)[~sfImmutableFlags].value_or(0) & lsifMPTCanHoldConfidentialBalance) != 0);

            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .err = tecNO_PERMISSION});
        }

        // Invalid ImmutableFlags bits.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.immutableFlags = 0x00000001u, .err = temINVALID_FLAG});
        }
    }

    void
    testSetKeysAndFlags()
    {
        testcase("set encryption keys and confidential flag");
        using namespace jtx;

        // Happy path: enable + upload valid keys.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G});
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(sle->isFieldPresent(sfAuditorEncryptionKey));
            BEAST_EXPECT(strHex(sle->getFieldVL(sfIssuerEncryptionKey)) == kKeyG);
            BEAST_EXPECT(strHex(sle->getFieldVL(sfAuditorEncryptionKey)) == kKey2G);
        }

        // Auditor without issuer on THIS tx → temMALFORMED.
        // Spec §12.4.1.3 is harsh: even if the issuance already has an issuer
        // key, a tx that carries auditor without issuer is temMALFORMED.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
            mpt.set({.auditorEncryptionKey = kKey2G, .err = temMALFORMED});
        }

        // Bad key length / invalid point → temMALFORMED.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyShort,
                 .err = temMALFORMED});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyInvalidPoint,
                 .err = temMALFORMED});
        }

        // Keys already present → tecNO_PERMISSION (write-once).
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G});
            mpt.set({.issuerEncryptionKey = kKey2G, .err = tecNO_PERMISSION});
            mpt.set(
                {.issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKeyG,
                 .err = tecNO_PERMISSION});
        }

        // Keys without lsf and without set-flag → tecNO_PERMISSION.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.set({.issuerEncryptionKey = kKeyG, .err = tecNO_PERMISSION});
        }

        // Re-setting the flag when already set is a no-op success.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance, .issuerEncryptionKey = kKeyG});
            mpt.set({.flags = tfMPTSetCanHoldConfidentialBalance});
            BEAST_EXPECT(env.le(keylet::mptIssuance(mpt.issuanceID()))
                             ->isFlag(lsfMPTCanHoldConfidentialBalance));
        }

        // Holder + keys in same tx → temMALFORMED.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.holders = {bob}, .fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer});
            mpt.authorize({.account = bob});
            mpt.set(
                {.holder = bob,
                 .flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .err = temMALFORMED});
        }
    }

    void
    testTransferFeeMutex()
    {
        testcase("transfer fee / confidential mutex");
        using namespace jtx;

        // Set flag while transfer fee nonzero → tecNO_PERMISSION.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.transferFee = 100,
                 .ownerCount = 1,
                 .flags = tfMPTCanTransfer,
                 .mutableFlags = tmfMPTCanMutateTransferFee});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .err = tecNO_PERMISSION});
        }

        // Set transfer fee while confidential enabled → tecNO_PERMISSION.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.ownerCount = 1,
                 .flags = tfMPTCanTransfer | tfMPTCanHoldConfidentialBalance,
                 .mutableFlags = tmfMPTCanMutateTransferFee});
            mpt.set({.transferFee = 100, .err = tecNO_PERMISSION});
        }

        // Same tx: nonzero TransferFee AND set-flag → temBAD_TRANSFER_FEE.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.ownerCount = 1,
                 .flags = tfMPTCanTransfer,
                 .mutableFlags = tmfMPTCanMutateTransferFee});
            mpt.set(
                {.flags = tfMPTSetCanHoldConfidentialBalance,
                 .transferFee = 100,
                 .issuerEncryptionKey = kKeyG,
                 .err = temBAD_TRANSFER_FEE});
        }
    }

    void
    testDestroyWithCOA()
    {
        testcase("destroy blocked when confidential outstanding > 0");
        using namespace jtx;

        Env env{*this, withConfidential()};
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();

        // close=false: open-ledger SLE edits are discarded by Env::close(),
        // and MPTTester::submit closes by default after every tx.
        MPTTester mpt(env, alice, {.fund = false, .close = false});
        mpt.create({.ownerCount = 1, .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer});
        env.close();

        auto injectCOA = [&](std::uint64_t value) {
            // Bypass ledger safety (see AccountSet_test). Do not env.close()
            // between this and the destroy submission — close() rebuilds the
            // open ledger from the last closed ledger and drops these edits.
            // Spec §12.4.2.4 says "field is already present"; this tree uses
            // SoeDefault (absent reads as 0), so interpret as COA > 0.
            auto const ok = env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
                auto const sle = view.read(keylet::mptIssuance(mpt.issuanceID()));
                if (!sle)
                    return false;

                // SLE copy+applyTemplate throws when a SoeDefault field is
                // present at its default (e.g. TransferFee=0). Build a free
                // STObject, omit those defaults, then construct the SLE.
                STObject fields{sfLedgerEntry};
                for (auto const& field : *sle)
                {
                    if (field.isDefault() &&
                        (field.getFName() == sfTransferFee || field.getFName() == sfAssetScale ||
                         field.getFName() == sfMutableFlags ||
                         field.getFName() == sfConfidentialOutstandingAmount))
                        continue;
                    xrpl::detail::STVar var{field};
                    fields.set(std::move(var.get()));
                }

                auto replacement = std::make_shared<SLE>(fields, sle->key());
                if (value == 0)
                {
                    if (replacement->isFieldPresent(sfConfidentialOutstandingAmount))
                        replacement->makeFieldAbsent(sfConfidentialOutstandingAmount);
                }
                else
                {
                    (*replacement)[sfConfidentialOutstandingAmount] = value;
                }
                view.rawReplace(replacement);
                return true;
            });
            BEAST_EXPECT(ok);
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle && (*sle)[sfConfidentialOutstandingAmount] == value);
        };

        injectCOA(1);
        mpt.destroy({.ownerCount = 1, .err = tecHAS_OBLIGATIONS});

        injectCOA(0);
        mpt.destroy({.ownerCount = 0});
    }

    void
    testDelegateConfidential()
    {
        testcase("delegate: granular rejects confidential; full set allows");
        using namespace jtx;

        auto assertNoConfidential = [&](Env& env, MPTTester const& mpt) {
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(!sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(!sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(!sle->isFieldPresent(sfAuditorEncryptionKey));
        };

        auto assertNoKeys = [&](Env& env, MPTTester const& mpt) {
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(!sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(!sle->isFieldPresent(sfAuditorEncryptionKey));
        };

        // Granular lock/unlock must not enable confidential flag.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(100000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer | tfMPTCanLock});
            env(delegate::set(alice, bob, {"MPTokenIssuanceLock", "MPTokenIssuanceUnlock"}));
            env.close();

            mpt.set(
                {.account = alice,
                 .flags = tfMPTSetCanHoldConfidentialBalance,
                 .delegate = bob,
                 .err = terNO_DELEGATE_PERMISSION});
            assertNoConfidential(env, mpt);

            mpt.set(
                {.account = alice,
                 .flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G,
                 .delegate = bob,
                 .err = terNO_DELEGATE_PERMISSION});
            assertNoConfidential(env, mpt);

            // Granular lock still works.
            mpt.set({.account = alice, .flags = tfMPTLock, .delegate = bob});
            BEAST_EXPECT(env.le(keylet::mptIssuance(mpt.issuanceID()))->isFlag(lsfMPTLocked));
        }

        // Granular lock/unlock must not upload write-once encryption keys.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(100000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create(
                {.ownerCount = 1,
                 .flags = tfMPTCanHoldConfidentialBalance | tfMPTCanTransfer | tfMPTCanLock});
            env(delegate::set(alice, bob, {"MPTokenIssuanceLock", "MPTokenIssuanceUnlock"}));
            env.close();

            mpt.set(
                {.account = alice,
                 .issuerEncryptionKey = kKeyG,
                 .delegate = bob,
                 .err = terNO_DELEGATE_PERMISSION});
            assertNoKeys(env, mpt);

            mpt.set(
                {.account = alice,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G,
                 .delegate = bob,
                 .err = terNO_DELEGATE_PERMISSION});
            assertNoKeys(env, mpt);
        }

        // Full MPTokenIssuanceSet permission may enable confidential and upload keys.
        {
            Env env{*this, withConfidential()};
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(100000), alice, bob);
            env.close();

            MPTTester mpt(env, alice, {.fund = false});
            mpt.create({.ownerCount = 1, .flags = tfMPTCanTransfer | tfMPTCanLock});
            env(delegate::set(alice, bob, {"MPTokenIssuanceSet"}));
            env.close();

            mpt.set(
                {.account = alice,
                 .flags = tfMPTSetCanHoldConfidentialBalance,
                 .issuerEncryptionKey = kKeyG,
                 .auditorEncryptionKey = kKey2G,
                 .delegate = bob});
            auto const sle = env.le(keylet::mptIssuance(mpt.issuanceID()));
            BEAST_EXPECT(sle);
            BEAST_EXPECT(sle->isFlag(lsfMPTCanHoldConfidentialBalance));
            BEAST_EXPECT(sle->isFieldPresent(sfIssuerEncryptionKey));
            BEAST_EXPECT(sle->isFieldPresent(sfAuditorEncryptionKey));
            BEAST_EXPECT(strHex(sle->getFieldVL(sfIssuerEncryptionKey)) == kKeyG);
            BEAST_EXPECT(strHex(sle->getFieldVL(sfAuditorEncryptionKey)) == kKey2G);
        }
    }

    void
    run() override
    {
        testAmendmentDisabled();
        testCreateConfidential();
        testSetKeysAndFlags();
        testTransferFeeMutex();
        testDestroyWithCOA();
        testDelegateConfidential();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTIssuance, app, xrpl);

}  // namespace test
}  // namespace xrpl
