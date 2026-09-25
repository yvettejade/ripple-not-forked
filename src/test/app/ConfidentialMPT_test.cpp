#include <test/jtx.h>
#include <test/jtx/mpt.h>
#include <test/jtx/ticket.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/ledger/Sandbox.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/ConfidentialProofs.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/tx/ApplyContext.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace xrpl {

// Implemented in applySteps.cpp for tests.
std::unique_ptr<Transactor>
makeTransactor(ApplyContext& ctx);

}  // namespace xrpl

namespace xrpl::test {

using namespace confidential;

namespace {

struct ConvertArgs
{
    std::uint64_t amount = 100;
    Scalar randomness = Scalar::fromUint64(7);
    bool registerKey = true;
    std::optional<std::uint32_t> ticket = std::nullopt;
};

}  // namespace

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    // An ElGamal key pair with secret k.
    struct Key
    {
        Scalar secret;
        Point pub;

        explicit Key(std::uint64_t k) : secret(Scalar::fromUint64(k)), pub(mulGenerator(secret))
        {
        }

        [[nodiscard]] std::string
        hex() const
        {
            auto const bytes = pub.bytes();
            return bytes ? strHex(*bytes) : std::string{};
        }
    };

    struct Issuance
    {
        MPTID id;
        Key issuer{101};
        std::optional<Key> auditor;
    };

    static std::string
    hex(ElGamalCiphertext const& ct)
    {
        auto const buf = ct.toBuffer();
        return buf ? strHex(Slice{*buf}) : std::string{};
    }

    static std::optional<ElGamalCiphertext>
    stored(SLE const& sle, SF_VL const& field)
    {
        if (!sle.isFieldPresent(field))
            return std::nullopt;
        return ElGamalCiphertext::fromBytes(makeSlice(sle.getFieldVL(field)));
    }

    // True if ct decrypts to m under the secret key.
    static bool
    decrypts(std::optional<ElGamalCiphertext> const& ct, Key const& key, std::uint64_t m)
    {
        return ct && ct->c2 - key.secret * ct->c1 == mulGenerator(Scalar::fromUint64(m));
    }

    static std::string
    confidentialFee(jtx::Env& env)
    {
        return to_string(env.current()->fees().base * 10);
    }

    // Directly edit the open ledger; the edit is lost when the ledger closes.
    static void
    modifyEntry(jtx::Env& env, Keylet const& k, std::function<void(SLE&)> const& f)
    {
        env.app().getOpenLedger().modify([&](OpenView& view, beast::Journal) {
            Sandbox sb(&view, TapNone);
            auto sle = sb.peek(k);
            if (!sle)
                return false;
            f(*sle);
            sb.update(sle);
            sb.apply(view);
            return true;
        });
    }

    // gw issues a confidential MPT, pays 1000 to each holder and registers
    // the issuer (and auditor) key.
    static Issuance
    issue(
        jtx::Env& env,
        jtx::Account const& gw,
        std::vector<jtx::Account> const& holders,
        std::uint32_t flags = tfMPTCanHoldConfidentialBalance,
        bool withAuditor = false,
        bool withKeys = true)
    {
        using namespace jtx;
        MPTTester const mpt(
            {.env = env,
             .issuer = gw,
             .holders = holders,
             .pay = 1'000,
             .flags = kMptDexFlags | flags,
             .authHolder = (flags & tfMPTRequireAuth) != 0u});
        Issuance result{.id = mpt.issuanceID()};
        if (withAuditor)
            result.auditor.emplace(102);
        if (withKeys)
        {
            json::Value jv;
            jv[jss::TransactionType] = jss::MPTokenIssuanceSet;
            jv[jss::Account] = gw.human();
            jv[sfMPTokenIssuanceID.jsonName] = to_string(result.id);
            jv[sfIssuerEncryptionKey.jsonName] = result.issuer.hex();
            if (result.auditor)
                jv[sfAuditorEncryptionKey.jsonName] = result.auditor->hex();
            env(jv);
            env.close();
        }
        return result;
    }

    static json::Value
    issuanceSetJV(
        jtx::Account const& gw,
        MPTID const& id,
        std::uint32_t flags,
        std::optional<jtx::Account> const& holder = std::nullopt)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::MPTokenIssuanceSet;
        jv[jss::Account] = gw.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(id);
        jv[jss::Flags] = flags;
        if (holder)
            jv[sfHolder.jsonName] = holder->human();
        return jv;
    }

    // A valid Convert of args.amount by holder, with a proof of knowledge
    // of key when it registers the key.
    static json::Value
    convertJV(
        jtx::Env& env,
        jtx::Account const& holder,
        Key const& key,
        Issuance const& issuance,
        ConvertArgs const& args = {})
    {
        auto const m = Scalar::fromUint64(args.amount);
        auto const& r = args.randomness;
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTConvert;
        jv[jss::Account] = holder.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(issuance.id);
        jv[sfMPTAmount.jsonName] = std::to_string(args.amount);
        jv[sfHolderEncryptedAmount.jsonName] = hex(elGamalEncrypt(m, r, key.pub));
        jv[sfIssuerEncryptedAmount.jsonName] = hex(elGamalEncrypt(m, r, issuance.issuer.pub));
        if (issuance.auditor)
            jv[sfAuditorEncryptedAmount.jsonName] =
                hex(elGamalEncrypt(m, r, issuance.auditor->pub));
        jv[sfBlindingFactor.jsonName] = strHex(r.bytes());
        std::uint32_t sequence = env.seq(holder);
        if (args.ticket)
        {
            jv[jss::Sequence] = 0;
            jv[sfTicketSequence.jsonName] = *args.ticket;
            sequence = *args.ticket;
        }
        if (args.registerKey)
        {
            jv[sfHolderEncryptionKey.jsonName] = key.hex();
            auto const ctx = transactionContextID(
                ttCONFIDENTIAL_MPT_CONVERT, holder.id(), issuance.id, sequence, holder.id(), 0);
            jv[sfZKProof.jsonName] = strHex(proveKnowledge(key.secret, ctx));
        }
        jv[jss::Fee] = confidentialFee(env);
        return jv;
    }

    static json::Value
    mergeJV(jtx::Env& env, jtx::Account const& holder, MPTID const& id)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTMergeInbox;
        jv[jss::Account] = holder.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(id);
        jv[jss::Fee] = confidentialFee(env);
        return jv;
    }

    void
    testConvertPreflight()
    {
        testcase("Convert preflight");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        {
            Env env{*this, testableAmendments() - featureConfidentialTransfer};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            Issuance const iss{.id = makeMptID(1, gw)};
            env(convertJV(env, alice, key, iss), Ter(temDISABLED));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(env, gw, {alice});

        // Only holders convert.
        env(convertJV(env, gw, key, iss), Ter(temMALFORMED));

        // The proof of knowledge accompanies exactly the key it registers.
        {
            auto jv = convertJV(env, alice, key, iss);
            jv.removeMember(sfZKProof.jsonName);
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = convertJV(env, alice, key, iss);
            jv.removeMember(sfHolderEncryptionKey.jsonName);
            env(jv, Ter(temMALFORMED));
        }

        // The holder key must be a valid compressed point.
        for (auto const& badKey :
             {std::string(64, '1'),
              "02" + std::string(64, '0'),
              "04" + key.hex().substr(2),
              key.hex() + "00"})
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[sfHolderEncryptionKey.jsonName] = badKey;
            env(jv, Ter(temMALFORMED));
        }

        // The blinding factor must be a canonical scalar.
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[sfBlindingFactor.jsonName] = std::string(64, 'F');
            env(jv, Ter(temMALFORMED));
        }

        // The proof of knowledge is exactly 64 bytes.
        for (auto const size : {63, 65})
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[sfZKProof.jsonName] = jv[sfZKProof.jsonName].asString().substr(0, 126) +
                std::string(size == 63 ? 0 : 4, 'A');
            env(jv, Ter(temMALFORMED));
        }

        // Every ciphertext must be two valid compressed points.
        auto const issAudited = [&] {
            auto copy = iss;
            copy.auditor.emplace(102);
            return copy;
        }();
        for (SF_VL const* field :
             {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount, &sfAuditorEncryptedAmount})
        {
            auto const good = convertJV(env, alice, key, issAudited)[field->jsonName].asString();
            for (auto const& bad :
                 {good.substr(0, 130),
                  good + "00",
                  "04" + good.substr(2),
                  good.substr(0, 66) + "02" + std::string(64, '0')})
            {
                auto jv = convertJV(env, alice, key, issAudited);
                jv[field->jsonName] = bad;
                env(jv, Ter(temBAD_CIPHERTEXT));
            }
        }

        // MPTAmount is capped at the maximum MPT amount.
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[sfMPTAmount.jsonName] = std::to_string(kMaxMpTokenAmount + 1);
            env(jv, Ter(temBAD_AMOUNT));
        }

        // XLS-0096 section 14.2: ten times the base fee.
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[jss::Fee] = to_string(env.current()->fees().base * 10 - 1);
            env(jv, Ter(telINSUF_FEE_P));
        }
        env(convertJV(env, alice, key, iss));
    }

    void
    testConvertPreclaim()
    {
        testcase("Convert preclaim");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});

        // The issuance and the holder's MPToken must exist.
        {
            Issuance missing = iss;
            missing.id = makeMptID(999, gw);
            env(convertJV(env, alice, key, missing), Ter(tecOBJECT_NOT_FOUND));
            env(convertJV(env, carol, key, iss), Ter(tecOBJECT_NOT_FOUND));
        }

        // The issuance must allow confidential balances and have an issuer key.
        {
            MPTTester const plain({.env = env, .issuer = gw, .holders = {alice}, .pay = 1'000});
            Issuance const other{.id = plain.issuanceID()};
            env(convertJV(env, alice, key, other), Ter(tecNO_PERMISSION));

            auto const noKeys =
                issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, false, false);
            env(convertJV(env, alice, key, noKeys), Ter(tecNO_PERMISSION));
        }

        // The auditor ciphertext is present exactly when the issuance has an
        // auditor key.
        {
            auto const audited = issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, true);
            Issuance unaudited = audited;
            unaudited.auditor.reset();
            env(convertJV(env, alice, key, unaudited), Ter(tecNO_PERMISSION));

            Issuance extra = iss;
            extra.auditor.emplace(102);
            env(convertJV(env, alice, key, extra), Ter(tecNO_PERMISSION));
        }

        // The first Convert registers the key; later ones must not.
        env(convertJV(env, alice, key, iss, {.registerKey = false}), Ter(tecNO_PERMISSION));
        env(convertJV(env, alice, key, iss));
        env.close();
        env(convertJV(env, alice, key, iss), Ter(tecDUPLICATE));
        env(convertJV(env, alice, Key(12), iss), Ter(tecDUPLICATE));

        // The holder needs the public balance.
        env(convertJV(env, alice, key, iss, {.amount = 901, .registerKey = false}),
            Ter(tecINSUFFICIENT_FUNDS));

        // The disclosed blinding factor must reproduce every ciphertext.
        for (SF_VL const* field : {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount})
        {
            auto jv = convertJV(env, alice, key, iss, {.registerKey = false});
            jv[field->jsonName] = hex(elGamalEncrypt(
                Scalar::fromUint64(101),
                Scalar::fromUint64(7),
                field == &sfHolderEncryptedAmount ? key.pub : iss.issuer.pub));
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            // The ciphertexts are encrypted under the registered key only.
            auto jv = convertJV(env, alice, Key(12), iss, {.registerKey = false});
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto jv = convertJV(env, alice, key, iss, {.registerKey = false});
            jv[sfBlindingFactor.jsonName] = strHex(Scalar::fromUint64(8).bytes());
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            // A zero blinding factor reproduces no valid ciphertext.
            auto jv = convertJV(env, alice, key, iss, {.registerKey = false});
            jv[sfBlindingFactor.jsonName] = std::string(64, '0');
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto const audited = issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, true);
            auto jv = convertJV(env, alice, key, audited);
            jv[sfAuditorEncryptedAmount.jsonName] = hex(elGamalEncrypt(
                Scalar::fromUint64(101), Scalar::fromUint64(7), audited.auditor->pub));
            env(jv, Ter(tecBAD_PROOF));
            env(convertJV(env, alice, key, audited));
        }

        // The proof of knowledge is bound to the key and the transaction.
        {
            auto jv = convertJV(env, bob, Key(12), iss);
            jv[sfZKProof.jsonName] = convertJV(env, bob, key, iss)[sfZKProof.jsonName];
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto jv = convertJV(env, bob, key, iss);
            auto const wrongContext = transactionContextID(
                ttCONFIDENTIAL_MPT_CONVERT, bob.id(), iss.id, env.seq(bob) + 1, bob.id(), 0);
            jv[sfZKProof.jsonName] = strHex(proveKnowledge(key.secret, wrongContext));
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            // A proof made for another holder does not transfer.
            auto jv = convertJV(env, alice, key, iss);
            auto const proof = jv[sfZKProof.jsonName];
            jv = convertJV(env, bob, key, iss);
            jv[sfZKProof.jsonName] = proof;
            env(jv, Ter(tecBAD_PROOF));
        }

        // A ticketed Convert binds the proof to the ticket sequence.
        {
            std::uint32_t const ticket = env.seq(bob) + 1;
            env(ticket::create(bob, 2));
            env.close();
            auto jv = convertJV(env, bob, key, iss, {.ticket = ticket});
            auto const wrongContext = transactionContextID(
                ttCONFIDENTIAL_MPT_CONVERT, bob.id(), iss.id, env.seq(bob), bob.id(), 0);
            jv[sfZKProof.jsonName] = strHex(proveKnowledge(key.secret, wrongContext));
            env(jv, Ter(tecBAD_PROOF));
            env(convertJV(env, bob, key, iss, {.ticket = ticket + 1}));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, bob));
            BEAST_EXPECT(sle && sle->isFieldPresent(sfHolderEncryptionKey));
        }
    }

    void
    testConvertAuthAndLock()
    {
        testcase("Convert authorization and locks");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(
            env, gw, {alice}, tfMPTCanHoldConfidentialBalance | tfMPTRequireAuth | tfMPTCanLock);

        // Each step closes the ledger, which replays transactions in
        // canonical rather than submission order.
        auto const step = [&](json::Value const& jv, TER ter = tesSUCCESS) {
            env(jv, Ter(ter));
            env.close();
        };

        // Locked funds must not move (individual and global locks).
        step(issuanceSetJV(gw, iss.id, tfMPTLock, alice));
        step(convertJV(env, alice, key, iss), tecLOCKED);
        step(issuanceSetJV(gw, iss.id, tfMPTUnlock, alice));
        step(issuanceSetJV(gw, iss.id, tfMPTLock));
        step(convertJV(env, alice, key, iss), tecLOCKED);
        step(issuanceSetJV(gw, iss.id, tfMPTUnlock));

        // An unauthorized holder cannot convert.
        {
            json::Value jv;
            jv[jss::TransactionType] = jss::MPTokenAuthorize;
            jv[jss::Account] = gw.human();
            jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
            jv[sfHolder.jsonName] = alice.human();
            jv[jss::Flags] = tfMPTUnauthorize;
            step(jv);
            step(convertJV(env, alice, key, iss), tecNO_AUTH);
            jv[jss::Flags] = 0;
            step(jv);
        }
        step(convertJV(env, alice, key, iss));
        auto const sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 900);
    }

    void
    testConvertApply()
    {
        testcase("Convert apply");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        for (bool const withAuditor : {false, true})
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            auto const iss = issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, withAuditor);

            auto const balance = env.balance(alice).value().xrp();
            env(convertJV(env, alice, key, iss, {.amount = 100}));
            env.close();
            BEAST_EXPECT(
                env.balance(alice).value().xrp() == balance - env.current()->fees().base * 10);

            // Section 7.5: the key, encrypted zeros and version 0, then the
            // inbox and mirrors are credited.
            auto sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            auto const r1 = Scalar::fromUint64(7);
            auto const m1 = Scalar::fromUint64(100);
            BEAST_EXPECT(strHex(sle->getFieldVL(sfHolderEncryptionKey)) == key.hex());
            BEAST_EXPECT((*sle)[sfMPTAmount] == 900);
            BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 0);
            BEAST_EXPECT(
                stored(*sle, sfConfidentialBalanceSpending) ==
                encryptedZero(alice.id(), iss.id, key.pub));
            BEAST_EXPECT(
                stored(*sle, sfConfidentialBalanceInbox) ==
                encryptedZero(alice.id(), iss.id, key.pub) + elGamalEncrypt(m1, r1, key.pub));
            BEAST_EXPECT(
                stored(*sle, sfIssuerEncryptedBalance) ==
                encryptedZero(alice.id(), iss.id, iss.issuer.pub) +
                    elGamalEncrypt(m1, r1, iss.issuer.pub));
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 0));
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 100));
            BEAST_EXPECT(decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, 100));
            BEAST_EXPECT(sle->isFieldPresent(sfAuditorEncryptedBalance) == withAuditor);
            if (withAuditor)
            {
                BEAST_EXPECT(decrypts(stored(*sle, sfAuditorEncryptedBalance), *iss.auditor, 100));
            }

            auto issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 100);
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 1'000);

            // Later Converts only credit the inbox and mirrors.
            env(convertJV(
                env,
                alice,
                key,
                iss,
                {.amount = 250, .randomness = Scalar::fromUint64(9), .registerKey = false}));
            env.close();
            sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            BEAST_EXPECT((*sle)[sfMPTAmount] == 650);
            BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 0);
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 0));
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 350));
            BEAST_EXPECT(decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, 350));
            if (withAuditor)
            {
                BEAST_EXPECT(decrypts(stored(*sle, sfAuditorEncryptedBalance), *iss.auditor, 350));
            }
            issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 350);

            // Converting nothing and the whole public balance both work.
            env(convertJV(env, alice, key, iss, {.amount = 0, .registerKey = false}));
            env(convertJV(env, alice, key, iss, {.amount = 650, .registerKey = false}));
            env.close();
            sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 0);
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 1'000));
            issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 1'000);
        }

        // A key can be registered without converting anything.
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            auto const iss = issue(env, gw, {alice});
            env(convertJV(env, alice, key, iss, {.amount = 0}));
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 1'000);
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 0));
        }
    }

    // A holder who knows the public encrypted-zero randomness can pick a
    // blinding factor that cancels a stored C1; such results are rejected.
    void
    testIdentityResults()
    {
        testcase("Identity results");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        auto const setup = [&](Env& env, bool withAuditor = false) {
            env.fund(XRP(10'000), gw, alice);
            env.close();
            return issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, withAuditor);
        };
        auto const r1 = Scalar::fromUint64(7);

        // Knowing the secret key of the inbox or of either mirror is enough
        // to cancel that ciphertext's C2 alone: after converting 100 with r1,
        // a Convert of 50 with r2 = -150 / sk - r0 - r1 leaves C2 at infinity.
        for (int target = 0; target < 3; ++target)
        {
            Env env{*this};
            auto const iss = setup(env, true);
            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            Key const& victim = target == 0 ? key : (target == 1 ? iss.issuer : *iss.auditor);
            env(convertJV(env, alice, key, iss, {.randomness = r1}));
            env.close();
            auto const r2 = -(Scalar::fromUint64(150) * victim.secret.inverse()) - r0 - r1;
            env(convertJV(
                    env, alice, key, iss, {.amount = 50, .randomness = r2, .registerKey = false}),
                Ter(tecBAD_PROOF));
            env(convertJV(env, alice, key, iss, {.amount = 50, .registerKey = false}));
        }

        // The inbox C1 cancels.
        {
            Env env{*this};
            auto const iss = setup(env);
            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            env(convertJV(env, alice, key, iss, {.randomness = r1}));
            env.close();
            auto const before = env.le(keylet::mptoken(iss.id, alice));
            env(convertJV(env, alice, key, iss, {.randomness = -(r0 + r1), .registerKey = false}),
                Ter(tecBAD_PROOF));
            env.close();
            auto const after = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(
                before && after &&
                before->getFieldVL(sfConfidentialBalanceInbox) ==
                    after->getFieldVL(sfConfidentialBalanceInbox));
        }

        // After a merge the inbox restarts at EncZero, so only the issuer
        // mirror cancels.
        {
            Env env{*this};
            auto const iss = setup(env);
            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            env(convertJV(env, alice, key, iss, {.randomness = r1}));
            env(mergeJV(env, alice, iss.id));
            env.close();
            env(convertJV(env, alice, key, iss, {.randomness = -(r0 + r1), .registerKey = false}),
                Ter(tecBAD_PROOF));
        }

        // Merging an inbox whose C1 cancels the spending balance's.
        {
            Env env{*this};
            auto const iss = setup(env);
            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            env(convertJV(env, alice, key, iss, {.randomness = -(r0 + r0)}));
            env.close();
            env(mergeJV(env, alice, iss.id), Ter(tecBAD_PROOF));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 0);
        }
    }

    void
    testMergeInbox()
    {
        testcase("MergeInbox");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const key(11);

        {
            Env env{*this, testableAmendments() - featureConfidentialTransfer};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            env(mergeJV(env, alice, makeMptID(1, gw)), Ter(temDISABLED));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(
            env,
            gw,
            {alice, bob},
            tfMPTCanHoldConfidentialBalance | tfMPTRequireAuth | tfMPTCanLock);

        env(mergeJV(env, gw, iss.id), Ter(temMALFORMED));
        env(mergeJV(env, alice, makeMptID(999, gw)), Ter(tecOBJECT_NOT_FOUND));
        env(mergeJV(env, carol, iss.id), Ter(tecOBJECT_NOT_FOUND));

        // The issuance must allow confidential balances.
        {
            MPTTester const plain({.env = env, .issuer = gw, .holders = {alice}, .pay = 1'000});
            env(mergeJV(env, alice, plain.issuanceID()), Ter(tecNO_PERMISSION));
        }

        // The MPToken must be initialized.
        env(mergeJV(env, alice, iss.id), Ter(tecNO_PERMISSION));
        env(convertJV(env, alice, key, iss, {.amount = 100}));
        env(convertJV(env, bob, Key(21), iss, {.amount = 5}));
        env.close();

        // Section 9.2.1.2: authorization and both locks. Each step closes the
        // ledger, which replays transactions in canonical rather than
        // submission order.
        auto const step = [&](json::Value const& jv, TER ter = tesSUCCESS) {
            env(jv, Ter(ter));
            env.close();
        };
        {
            json::Value jv;
            jv[jss::TransactionType] = jss::MPTokenAuthorize;
            jv[jss::Account] = gw.human();
            jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
            jv[sfHolder.jsonName] = alice.human();
            jv[jss::Flags] = tfMPTUnauthorize;
            step(jv);
            step(mergeJV(env, alice, iss.id), tecNO_AUTH);
            jv[jss::Flags] = 0;
            step(jv);
        }
        step(issuanceSetJV(gw, iss.id, tfMPTLock, alice));
        step(mergeJV(env, alice, iss.id), tecLOCKED);
        step(mergeJV(env, bob, iss.id));
        step(issuanceSetJV(gw, iss.id, tfMPTUnlock, alice));
        step(issuanceSetJV(gw, iss.id, tfMPTLock));
        step(mergeJV(env, alice, iss.id), tecLOCKED);
        step(issuanceSetJV(gw, iss.id, tfMPTUnlock));

        // Section 9.3: the inbox moves into the spending balance, the inbox
        // resets to EncZero and the version advances.
        auto const zero = encryptedZero(alice.id(), iss.id, key.pub);
        auto before = env.le(keylet::mptoken(iss.id, alice));
        env(mergeJV(env, alice, iss.id));
        env.close();
        auto after = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(before && after))
            return;
        BEAST_EXPECT(
            stored(*after, sfConfidentialBalanceSpending) ==
            *stored(*before, sfConfidentialBalanceSpending) +
                *stored(*before, sfConfidentialBalanceInbox));
        BEAST_EXPECT(stored(*after, sfConfidentialBalanceInbox) == zero);
        BEAST_EXPECT(
            after->getFieldVL(sfIssuerEncryptedBalance) ==
            before->getFieldVL(sfIssuerEncryptedBalance));
        BEAST_EXPECT((*after)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT((*after)[sfMPTAmount] == 900);
        BEAST_EXPECT(decrypts(stored(*after, sfConfidentialBalanceSpending), key, 100));
        BEAST_EXPECT(decrypts(stored(*after, sfConfidentialBalanceInbox), key, 0));
        auto issuance = env.le(keylet::mptIssuance(iss.id));
        BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 105);

        // Merging an empty inbox is a valid no-op that still bumps the version.
        env(mergeJV(env, alice, iss.id));
        env.close();
        after = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(after))
            return;
        BEAST_EXPECT((*after)[sfConfidentialBalanceVersion] == 2);
        BEAST_EXPECT(decrypts(stored(*after, sfConfidentialBalanceSpending), key, 100));
        BEAST_EXPECT(stored(*after, sfConfidentialBalanceInbox) == zero);

        // The version wraps from 2^32 - 1 to 0.
        modifyEntry(env, keylet::mptoken(iss.id, alice), [](SLE& sle) {
            sle.setFieldU32(sfConfidentialBalanceVersion, 0xFFFF'FFFF);
        });
        env(mergeJV(env, alice, iss.id));
        after = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(after && (*after)[sfConfidentialBalanceVersion] == 0);

        // Section 14.2: ten times the base fee. The open ledger holds the
        // underpaying transaction for the next ledger, so this comes last.
        auto jv = mergeJV(env, alice, iss.id);
        jv[jss::Fee] = to_string(env.current()->fees().base * 10 - 1);
        env(jv, Ter(telINSUF_FEE_P));
    }

    // Transaction-specific invariants are disabled in Transactor; the protocol
    // invariant ValidConfidentialMPToken covers these transactions.
    void
    testTransactionInvariants()
    {
        testcase("Transaction invariants");
        using namespace jtx;

        Env env{*this};
        Account const alice("alice");
        OpenView ov{*env.current()};
        auto const check = [&]<class T>(TxType type) {
            STTx const tx{type, [&](STObject& obj) { obj.setAccountID(sfAccount, alice.id()); }};
            ApplyContext ac{
                env.app(), ov, tx, tesSUCCESS, env.current()->fees().base, TapNone, env.journal};
            auto transactor = makeTransactor(ac);
            auto* const derived = dynamic_cast<T*>(transactor.get());
            if (!BEAST_EXPECT(derived))
                return;
            derived->visitInvariantEntry(false, nullptr, nullptr);
            BEAST_EXPECT(derived->finalizeInvariants(tx, tesSUCCESS, XRPAmount{}, ov, env.journal));
        };
        check.operator()<ConfidentialMPTConvert>(ttCONFIDENTIAL_MPT_CONVERT);
        check.operator()<ConfidentialMPTMergeInbox>(ttCONFIDENTIAL_MPT_MERGE_INBOX);
    }

public:
    void
    run() override
    {
        testConvertPreflight();
        testConvertPreclaim();
        testConvertAuthAndLock();
        testConvertApply();
        testIdentityResults();
        testMergeInbox();
        testTransactionInvariants();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, app, xrpl);

}  // namespace xrpl::test
