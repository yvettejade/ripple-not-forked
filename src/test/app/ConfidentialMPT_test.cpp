#include <test/jtx.h>
#include <test/jtx/batch.h>
#include <test/jtx/credentials.h>
#include <test/jtx/delegate.h>
#include <test/jtx/deposit.h>
#include <test/jtx/escrow.h>
#include <test/jtx/mpt.h>
#include <test/jtx/tag.h>
#include <test/jtx/ticket.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/OpenView.h>
#include <xrpl/ledger/Sandbox.h>
#include <xrpl/protocol/Bulletproof.h>
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
#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <chrono>
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
    // The sequence the proof is bound to, if not the account's next one.
    std::optional<std::uint32_t> sequence = std::nullopt;
};

struct SendArgs
{
    std::uint64_t amount = 30;
    // The sender's spending balance the proof claims.
    std::uint64_t balance = 100;
    Scalar randomness = Scalar::fromUint64(23);
    Scalar blinding = Scalar::fromUint64(29);
    // The version the proof is bound to, if not the sender's current one.
    std::optional<std::uint32_t> version = std::nullopt;
    std::optional<std::uint32_t> ticket = std::nullopt;
    // The sequence the proof is bound to, if not the account's next one.
    std::optional<std::uint32_t> sequence = std::nullopt;
    // Range proof bytes to send instead of an honest proof.
    std::optional<Blob> rangeProof = std::nullopt;
};

struct ClawbackArgs
{
    // The issuer key the proof uses, if not the issuance's.
    std::optional<std::uint64_t> signingKey = std::nullopt;
    std::optional<std::uint32_t> ticket = std::nullopt;
    // The sequence the proof is bound to, if not the issuer's next one.
    std::optional<std::uint32_t> sequence = std::nullopt;
};

struct ConvertBackArgs
{
    std::uint64_t amount = 40;
    // The spending balance the proof claims.
    std::uint64_t balance = 100;
    Scalar randomness = Scalar::fromUint64(13);
    Scalar blinding = Scalar::fromUint64(17);
    // The version the proof is bound to, if not the holder's current one.
    std::optional<std::uint32_t> version = std::nullopt;
    std::optional<std::uint32_t> ticket = std::nullopt;
    // The sequence the proof is bound to, if not the account's next one.
    std::optional<std::uint32_t> sequence = std::nullopt;
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
        bool withKeys = true,
        std::uint32_t publicFlags = jtx::kMptDexFlags)
    {
        using namespace jtx;
        MPTTester const mpt(
            {.env = env,
             .issuer = gw,
             .holders = holders,
             .pay = 1'000,
             .flags = publicFlags | flags,
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
        std::uint32_t sequence = args.sequence.value_or(env.seq(holder));
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

    // A ConvertBack of args.amount from a spending balance of args.balance,
    // proved against the holder's current spending balance and version.
    static json::Value
    convertBackJV(
        jtx::Env& env,
        jtx::Account const& holder,
        Key const& key,
        Issuance const& issuance,
        ConvertBackArgs const& args = {})
    {
        auto const sle = env.le(keylet::mptoken(issuance.id, holder));
        auto const spending = sle ? stored(*sle, sfConfidentialBalanceSpending) : std::nullopt;
        std::uint32_t const version =
            args.version.value_or(sle ? sle->getFieldU32(sfConfidentialBalanceVersion) : 0);

        auto const m = Scalar::fromUint64(args.amount);
        auto const& r = args.randomness;
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        jv[jss::Account] = holder.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(issuance.id);
        jv[sfMPTAmount.jsonName] = std::to_string(args.amount);
        jv[sfHolderEncryptedAmount.jsonName] = hex(elGamalEncrypt(m, r, key.pub));
        jv[sfIssuerEncryptedAmount.jsonName] = hex(elGamalEncrypt(m, r, issuance.issuer.pub));
        if (issuance.auditor)
            jv[sfAuditorEncryptedAmount.jsonName] =
                hex(elGamalEncrypt(m, r, issuance.auditor->pub));
        jv[sfBlindingFactor.jsonName] = strHex(r.bytes());

        auto const commitment = pedersenCommit(Scalar::fromUint64(args.balance), args.blinding);
        jv[sfBalanceCommitment.jsonName] = strHex(*commitment.bytes());
        std::uint32_t sequence = args.sequence.value_or(env.seq(holder));
        if (args.ticket)
        {
            jv[jss::Sequence] = 0;
            jv[sfTicketSequence.jsonName] = *args.ticket;
            sequence = *args.ticket;
        }
        auto const ctx = transactionContextID(
            ttCONFIDENTIAL_MPT_CONVERT_BACK,
            holder.id(),
            issuance.id,
            sequence,
            holder.id(),
            version);
        // An uninitialized holder gets a proof over a stand-in balance.
        auto const balance = spending.value_or(
            elGamalEncrypt(Scalar::fromUint64(1), Scalar::fromUint64(1), key.pub));
        auto const sigma = proveBalance(
            {.key = key.pub, .balance = balance, .balanceCommitment = commitment},
            Scalar::fromUint64(args.balance),
            args.blinding,
            key.secret,
            ctx);
        // Wraps for an overdraft, so the proof opens a different commitment.
        std::array<std::uint64_t, 1> const remainder{args.balance - args.amount};
        std::array<Scalar, 1> const blinding{args.blinding};
        auto const range = proveRange(remainder, blinding, ctx);
        jv[sfZKProof.jsonName] = strHex(sigma) + strHex(range);
        jv[jss::Fee] = confidentialFee(env);
        return jv;
    }

    // A Send of args.amount from a spending balance of args.balance, proved
    // against the sender's current spending balance and version.
    static json::Value
    sendJV(
        jtx::Env& env,
        jtx::Account const& sender,
        Key const& senderKey,
        jtx::Account const& destination,
        Key const& destinationKey,
        Issuance const& issuance,
        SendArgs const& args = {})
    {
        auto const sle = env.le(keylet::mptoken(issuance.id, sender));
        auto const spending = sle ? stored(*sle, sfConfidentialBalanceSpending) : std::nullopt;
        std::uint32_t const version =
            args.version.value_or(sle ? sle->getFieldU32(sfConfidentialBalanceVersion) : 0);

        auto const m = Scalar::fromUint64(args.amount);
        auto const b = Scalar::fromUint64(args.balance);
        auto const& r = args.randomness;
        std::vector<Point> keys{senderKey.pub, destinationKey.pub, issuance.issuer.pub};
        if (issuance.auditor)
            keys.push_back(issuance.auditor->pub);
        std::vector<ElGamalCiphertext> cts;
        for (auto const& pk : keys)
            cts.push_back(elGamalEncrypt(m, r, pk));

        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTSend;
        jv[jss::Account] = sender.human();
        jv[jss::Destination] = destination.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(issuance.id);
        jv[sfSenderEncryptedAmount.jsonName] = hex(cts[0]);
        jv[sfDestinationEncryptedAmount.jsonName] = hex(cts[1]);
        jv[sfIssuerEncryptedAmount.jsonName] = hex(cts[2]);
        if (issuance.auditor)
            jv[sfAuditorEncryptedAmount.jsonName] = hex(cts[3]);

        auto const amountCommitment = pedersenCommit(m, r);
        auto const balanceCommitment = pedersenCommit(b, args.blinding);
        jv[sfAmountCommitment.jsonName] = strHex(*amountCommitment.bytes());
        jv[sfBalanceCommitment.jsonName] = strHex(*balanceCommitment.bytes());

        SendStatement statement{
            .recipientKeys = keys,
            .senderKey = senderKey.pub,
            .c1 = cts[0].c1,
            .c2 = {},
            .amountCommitment = amountCommitment,
            .balanceCommitment = balanceCommitment,
            // An uninitialized sender gets a proof over a stand-in balance.
            .balance = spending.value_or(
                elGamalEncrypt(Scalar::fromUint64(1), Scalar::fromUint64(1), senderKey.pub))};
        for (auto const& ct : cts)
            statement.c2.push_back(ct.c2);
        std::uint32_t sequence = args.sequence.value_or(env.seq(sender));
        if (args.ticket)
        {
            jv[jss::Sequence] = 0;
            jv[sfTicketSequence.jsonName] = *args.ticket;
            sequence = *args.ticket;
        }
        auto const ctx = transactionContextID(
            ttCONFIDENTIAL_MPT_SEND, sender.id(), issuance.id, sequence, destination.id(), version);
        auto const sigma = proveSend(
            statement,
            {.amount = m,
             .randomness = r,
             .balance = b,
             .balanceBlinding = args.blinding,
             .secretKey = senderKey.secret},
            ctx);
        // Wraps for an overdraft, so the proof opens a different commitment.
        std::array<std::uint64_t, 2> const values{args.amount, args.balance - args.amount};
        std::array<Scalar, 2> const blindings{r, args.blinding - r};
        jv[sfZKProof.jsonName] = strHex(sigma) +
            (args.rangeProof ? strHex(*args.rangeProof)
                             : strHex(proveRange(values, blindings, ctx)));
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

        // No transaction flags are defined.
        {
            auto jv = convertJV(env, alice, key, iss);
            jv[jss::Flags] = tfMPTLock;
            env(jv, Ter(temINVALID_FLAG));
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
        // Section 7.3.2 lists the funds check before the duplicate key.
        env(convertJV(env, alice, key, iss, {.amount = 901}), Ter(tecINSUFFICIENT_FUNDS));

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
        {
            auto jv = mergeJV(env, alice, iss.id);
            jv[jss::Flags] = tfMPTLock;
            env(jv, Ter(temINVALID_FLAG));
        }
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

    // MergeInbox leaves both mirrors alone: they already track spending plus
    // inbox.
    void
    testMergeInboxAudited()
    {
        testcase("MergeInbox with an auditor");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance, true);
        env(convertJV(env, alice, key, iss, {.amount = 70}));
        env.close();
        auto const before = env.le(keylet::mptoken(iss.id, alice));
        env(mergeJV(env, alice, iss.id));
        env.close();
        auto const after = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(before && after))
            return;
        for (SF_VL const* field : {&sfIssuerEncryptedBalance, &sfAuditorEncryptedBalance})
            BEAST_EXPECT(before->getFieldVL(*field) == after->getFieldVL(*field));
        BEAST_EXPECT(decrypts(stored(*after, sfConfidentialBalanceSpending), key, 70));
        BEAST_EXPECT(decrypts(stored(*after, sfAuditorEncryptedBalance), *iss.auditor, 70));
    }

    // XLS-0096 section 5.5: delegates operate an account; they cannot choose
    // the key that controls its confidential balance.
    void
    testDelegation()
    {
        testcase("Delegation");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        auto const setup = [&](Env& env) {
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            return issue(env, gw, {alice});
        };

        // Without a delegation entry. terNO_DELEGATE_PERMISSION is a retry
        // code, so this ledger history ends here.
        {
            Env env{*this};
            auto const iss = setup(env);
            env(convertJV(env, alice, key, iss), Ter(tesSUCCESS));
            env.close();
            env(convertJV(env, alice, key, iss, {.registerKey = false}),
                delegate::As(bob),
                Ter(terNO_DELEGATE_PERMISSION));
            env(mergeJV(env, alice, iss.id), delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        }

        Env env{*this};
        auto const iss = setup(env);
        env(delegate::set(
            alice,
            bob,
            {"ConfidentialMPTConvert", "ConfidentialMPTMergeInbox", "ConfidentialMPTConvertBack"}));
        env.close();

        // Only the holder registers its key.
        env(convertJV(env, alice, Key(12), iss), delegate::As(bob), Ter(terNO_DELEGATE_PERMISSION));
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && !sle->isFieldPresent(sfHolderEncryptionKey));
        env(convertJV(env, alice, key, iss, {.amount = 100}));
        env.close();

        // The delegate converts and merges under the holder's key and pays
        // the fee; the proofs are bound to the holder's account.
        auto const aliceXrp = env.balance(alice).value().xrp();
        auto const bobXrp = env.balance(bob).value().xrp();
        env(convertJV(env, alice, key, iss, {.amount = 50, .registerKey = false}),
            delegate::As(bob));
        env(mergeJV(env, alice, iss.id), delegate::As(bob));
        env.close();
        auto const fee = env.current()->fees().base * 10;
        BEAST_EXPECT(env.balance(alice).value().xrp() == aliceXrp);
        BEAST_EXPECT(env.balance(bob).value().xrp() == bobXrp - fee - fee);
        sle = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(sle))
            return;
        BEAST_EXPECT(strHex(sle->getFieldVL(sfHolderEncryptionKey)) == key.hex());
        BEAST_EXPECT((*sle)[sfMPTAmount] == 850);
        BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 150));

        // ConvertBack needs the holder's secret key for its proof; the
        // delegate only submits it.
        env(convertBackJV(env, alice, key, iss, {.amount = 30, .balance = 150}), delegate::As(bob));
        env.close();
        BEAST_EXPECT(env.balance(bob).value().xrp() == bobXrp - fee - fee - fee);
        sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 880);
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 120));
    }

    // Funds accumulate across repeated Convert and MergeInbox cycles.
    void
    testRepeatedMerges()
    {
        testcase("Repeated merges");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(env, gw, {alice});

        std::uint64_t total = 0;
        std::uint64_t r = 30;
        for (std::uint64_t const amount : {100, 50, 0, 25})
        {
            env(convertJV(
                env,
                alice,
                key,
                iss,
                {.amount = amount,
                 .randomness = Scalar::fromUint64(r++),
                 .registerKey = total == 0 && amount == 100}));
            env(mergeJV(env, alice, iss.id));
            env.close();
            total += amount;
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, total));
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 0));
            BEAST_EXPECT(decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, total));
            BEAST_EXPECT((*sle)[sfMPTAmount] == 1'000 - total);
        }
        auto const sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 4);
    }

    // Escrowed tokens are not part of the public balance Convert draws on.
    void
    testConvertEscrowed()
    {
        testcase("Convert with escrowed tokens");
        using namespace jtx;
        using namespace std::chrono;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob);
        env.close();
        auto const iss = issue(env, gw, {alice}, tfMPTCanHoldConfidentialBalance | tfMPTCanEscrow);
        MPT const mpt("MPT", iss.id);
        env(escrow::create(alice, bob, mpt(600)),
            escrow::kCondition(escrow::kCb1),
            escrow::kFinishTime(env.now() + 100s),
            Fee(env.current()->fees().base * 150));
        env.close();
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 400 && (*sle)[~sfLockedAmount] == 600);

        env(convertJV(env, alice, key, iss, {.amount = 401}), Ter(tecINSUFFICIENT_FUNDS));
        env(convertJV(env, alice, key, iss, {.amount = 400}));
        env.close();
        sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 0 && (*sle)[~sfLockedAmount] == 600);
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), key, 400));
    }

    // Inner Batch transactions pay their ten base fees in the outer fee, bind
    // their proofs to their own sequence and roll back with the batch.
    void
    testBatch()
    {
        testcase("Batch");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(env, gw, {alice});
        auto const base = env.current()->fees().base;
        auto const batchFee = base * 2 + base * 10 * 2;

        auto seq = env.seq(alice);
        env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
            batch::Inner(convertJV(env, alice, key, iss, {.sequence = seq + 1}), seq + 1),
            batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
        env.close();
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(sle))
            return;
        BEAST_EXPECT((*sle)[sfMPTAmount] == 900);
        BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 100));

        // A doApply failure (a cancelled inbox C1) rolls the whole batch back.
        auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
        auto const inbox = sle->getFieldVL(sfConfidentialBalanceInbox);
        seq = env.seq(alice);
        env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
            batch::Inner(
                convertJV(
                    env,
                    alice,
                    key,
                    iss,
                    {.amount = 10, .randomness = -r0, .registerKey = false, .sequence = seq + 1}),
                seq + 1),
            batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
        env.close();
        sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 900);
        BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 1);
        BEAST_EXPECT(sle && sle->getFieldVL(sfConfidentialBalanceInbox) == inbox);
        BEAST_EXPECT(env.seq(alice) == seq + 1);

        // The outer fee must cover each inner transaction's ten base fees.
        // The underpaying transaction is held for the next ledger, so this
        // comes last.
        seq = env.seq(alice);
        env(batch::outer(alice, seq, batchFee - XRPAmount{1}, tfAllOrNothing),
            batch::Inner(
                convertJV(env, alice, key, iss, {.registerKey = false, .sequence = seq + 1}),
                seq + 1),
            batch::Inner(mergeJV(env, alice, iss.id), seq + 2),
            Ter(telINSUF_FEE_P));
    }

    // Each multisigner adds one base fee to the ten base fees.
    void
    testMultisignFee()
    {
        testcase("Multisigned fee");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice});
        env(signers(alice, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        auto const base = env.current()->fees().base;
        auto jv = convertJV(env, alice, key, iss);
        jv[jss::Fee] = to_string(base * 12);
        env(jv, Msig(bob, carol));
        env.close();
        auto const sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && sle->isFieldPresent(sfHolderEncryptionKey));

        // The underpaying transaction is held for the next ledger, so this
        // comes last.
        jv = mergeJV(env, alice, iss.id);
        jv[jss::Fee] = to_string(base * 12 - 1);
        env(jv, Msig(bob, carol), Ter(telINSUF_FEE_P));
    }

    // alice registers `key` and converts 100, and bob converts 200 so that
    // COA exceeds alice's balance; both merge so the funds are spendable.
    static void
    fundConfidential(
        jtx::Env& env,
        jtx::Account const& alice,
        jtx::Account const& bob,
        Key const& key,
        Issuance const& iss)
    {
        env(convertJV(env, alice, key, iss, {.amount = 100}));
        env(convertJV(env, bob, Key(21), iss, {.amount = 200}));
        env.close();
        env(mergeJV(env, alice, iss.id));
        env(mergeJV(env, bob, iss.id));
        env.close();
    }

    void
    testConvertBackPreflight()
    {
        testcase("ConvertBack preflight");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        {
            Env env{*this, testableAmendments() - featureConfidentialTransfer};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            Issuance const iss{.id = makeMptID(1, gw)};
            env(convertBackJV(env, alice, key, iss), Ter(temDISABLED));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});
        fundConfidential(env, alice, bob, key, iss);

        env(convertBackJV(env, gw, key, iss), Ter(temMALFORMED));
        {
            auto jv = convertBackJV(env, alice, key, iss);
            jv[sfBlindingFactor.jsonName] = std::string(64, 'F');
            env(jv, Ter(temMALFORMED));
        }

        auto const issAudited = [&] {
            auto copy = iss;
            copy.auditor.emplace(102);
            return copy;
        }();
        for (SF_VL const* field :
             {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount, &sfAuditorEncryptedAmount})
        {
            auto const good =
                convertBackJV(env, alice, key, issAudited)[field->jsonName].asString();
            for (auto const& bad : {good.substr(0, 130), "04" + good.substr(2)})
            {
                auto jv = convertBackJV(env, alice, key, issAudited);
                jv[field->jsonName] = bad;
                env(jv, Ter(temBAD_CIPHERTEXT));
            }
        }

        // The balance commitment must be a valid point.
        for (auto const& bad :
             {std::string(64, '1'), "02" + std::string(64, '0'), key.hex() + "00"})
        {
            auto jv = convertBackJV(env, alice, key, iss);
            jv[sfBalanceCommitment.jsonName] = bad;
            env(jv, Ter(temMALFORMED));
        }

        // ZKProof is the 128-byte sigma proof and the 688-byte range proof.
        for (auto const size : {815, 817})
        {
            auto jv = convertBackJV(env, alice, key, iss);
            auto const proof = jv[sfZKProof.jsonName].asString();
            jv[sfZKProof.jsonName] = size == 815 ? proof.substr(0, 1630) : proof + "00";
            env(jv, Ter(temMALFORMED));
        }

        // Section 10.4.1: MPTAmount is non-zero and at most the maximum.
        {
            auto jv = convertBackJV(env, alice, key, iss);
            jv[sfMPTAmount.jsonName] = "0";
            env(jv, Ter(temBAD_AMOUNT));
            jv[sfMPTAmount.jsonName] = std::to_string(kMaxMpTokenAmount + 1);
            env(jv, Ter(temBAD_AMOUNT));
        }

        // The underpaying transaction is held for the next ledger, so this
        // comes last.
        auto jv = convertBackJV(env, alice, key, iss);
        jv[jss::Fee] = to_string(env.current()->fees().base * 10 - 1);
        env(jv, Ter(telINSUF_FEE_P));
    }

    void
    testConvertBackPreclaim()
    {
        testcase("ConvertBack preclaim");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const key(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob, carol});

        {
            Issuance missing = iss;
            missing.id = makeMptID(999, gw);
            env(convertBackJV(env, alice, key, missing), Ter(tecOBJECT_NOT_FOUND));
            Account const dave("dave");
            env.fund(XRP(10'000), dave);
            env.close();
            env(convertBackJV(env, dave, key, iss), Ter(tecOBJECT_NOT_FOUND));
        }
        {
            MPTTester const plain({.env = env, .issuer = gw, .holders = {alice}, .pay = 1'000});
            Issuance const other{.id = plain.issuanceID()};
            env(convertBackJV(env, alice, key, other), Ter(tecNO_PERMISSION));
        }

        // Section 10.4.2(3): the holder must have initialized.
        env(convertBackJV(env, carol, key, iss), Ter(tecNO_PERMISSION));

        fundConfidential(env, alice, bob, key, iss);

        // Section 10.4.2(4) and spec 4.8: auditor ciphertext exactly when the
        // issuance has an auditor key.
        {
            Issuance extra = iss;
            extra.auditor.emplace(102);
            env(convertBackJV(env, alice, key, extra), Ter(tecNO_PERMISSION));
        }

        // Section 10.4.2(5): COA bounds the amount (the range proof bounds
        // the holder's own balance).
        env(convertBackJV(env, alice, key, iss, {.amount = 301, .balance = 400}),
            Ter(tecINSUFFICIENT_FUNDS));

        // Section 10.4.2(6): the blinding factor must reproduce each ciphertext.
        for (SF_VL const* field : {&sfHolderEncryptedAmount, &sfIssuerEncryptedAmount})
        {
            auto jv = convertBackJV(env, alice, key, iss);
            jv[field->jsonName] = hex(elGamalEncrypt(
                Scalar::fromUint64(41),
                Scalar::fromUint64(13),
                field == &sfHolderEncryptedAmount ? key.pub : iss.issuer.pub));
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto jv = convertBackJV(env, alice, key, iss);
            jv[sfBlindingFactor.jsonName] = std::string(64, '0');
            env(jv, Ter(tecBAD_PROOF));
        }

        // Section 10.4.2(7): the sigma proof must open the spending balance.
        env(convertBackJV(env, alice, key, iss, {.balance = 101}), Ter(tecBAD_PROOF));
        env(convertBackJV(env, alice, Key(12), iss), Ter(tecBAD_PROOF));
        {
            // A valid sigma proof over the balance, spliced onto a range proof
            // for another commitment.
            auto jv = convertBackJV(env, alice, key, iss);
            auto const other =
                convertBackJV(env, alice, key, iss, {.blinding = Scalar::fromUint64(18)});
            jv[sfZKProof.jsonName] = jv[sfZKProof.jsonName].asString().substr(0, 256) +
                other[sfZKProof.jsonName].asString().substr(256);
            env(jv, Ter(tecBAD_PROOF));
        }

        // Section 10.4.2(8): the remainder must be in range. With b = 100 and
        // m = 150 the remainder commitment opens to q - 50.
        env(convertBackJV(env, alice, key, iss, {.amount = 150}), Ter(tecBAD_PROOF));

        // Proofs are bound to the spending balance version, the sequence and
        // the account.
        {
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            auto const version = sle->getFieldU32(sfConfidentialBalanceVersion);
            for (std::uint32_t const other : {version - 1, version + 1})
            {
                env(convertBackJV(env, alice, key, iss, {.version = other}), Ter(tecBAD_PROOF));
            }
        }
        {
            auto const early = convertBackJV(env, alice, key, iss);
            env(noop(alice));
            env(early, Ter(tecBAD_PROOF));
        }
        {
            auto jv = convertBackJV(env, bob, Key(21), iss, {.balance = 200});
            auto const aliceProof = convertBackJV(env, alice, key, iss);
            jv[sfZKProof.jsonName] = aliceProof[sfZKProof.jsonName];
            jv[sfBalanceCommitment.jsonName] = aliceProof[sfBalanceCommitment.jsonName];
            env(jv, Ter(tecBAD_PROOF));
        }

        env(convertBackJV(env, alice, key, iss));
    }

    void
    testConvertBackAuthAndFreeze()
    {
        testcase("ConvertBack authorization and freeze");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        auto const setup = [&](Env& env) {
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(
                env,
                gw,
                {alice, bob},
                tfMPTCanHoldConfidentialBalance | tfMPTRequireAuth | tfMPTCanLock);
            fundConfidential(env, alice, bob, key, iss);
            return iss;
        };

        // terFROZEN is a retry code: the transaction is held and retried in
        // the next ledger, so each lock gets its own ledger history.
        for (bool const global : {false, true})
        {
            Env env{*this};
            auto const iss = setup(env);
            if (global)
            {
                env(issuanceSetJV(gw, iss.id, tfMPTLock));
            }
            else
            {
                env(issuanceSetJV(gw, iss.id, tfMPTLock, alice));
            }
            env.close();
            env(convertBackJV(env, alice, key, iss), Ter(terFROZEN));
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfMPTAmount] == 900);
        }

        {
            Env env{*this};
            auto const iss = setup(env);
            json::Value jv;
            jv[jss::TransactionType] = jss::MPTokenAuthorize;
            jv[jss::Account] = gw.human();
            jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
            jv[sfHolder.jsonName] = alice.human();
            jv[jss::Flags] = tfMPTUnauthorize;
            env(jv);
            env.close();
            env(convertBackJV(env, alice, key, iss), Ter(tecNO_AUTH));
            env.close();
            jv[jss::Flags] = 0;
            env(jv);
            env.close();
            env(convertBackJV(env, alice, key, iss));
        }
    }

    void
    testConvertBackApply()
    {
        testcase("ConvertBack apply");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        for (bool const withAuditor : {false, true})
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss =
                issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, withAuditor);
            fundConfidential(env, alice, bob, key, iss);

            auto before = env.le(keylet::mptoken(iss.id, alice));
            env(convertBackJV(env, alice, key, iss, {.amount = 40}));
            env.close();
            auto after = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(before && after))
                return;

            // Section 10.5 and updated spec eq. (42)-(45).
            auto const m = Scalar::fromUint64(40);
            auto const r = Scalar::fromUint64(13);
            BEAST_EXPECT((*after)[sfMPTAmount] == 940);
            BEAST_EXPECT(
                (*after)[sfConfidentialBalanceVersion] ==
                (*before)[sfConfidentialBalanceVersion] + 1);
            BEAST_EXPECT(
                stored(*after, sfConfidentialBalanceSpending) ==
                *stored(*before, sfConfidentialBalanceSpending) - elGamalEncrypt(m, r, key.pub));
            BEAST_EXPECT(
                after->getFieldVL(sfConfidentialBalanceInbox) ==
                before->getFieldVL(sfConfidentialBalanceInbox));
            BEAST_EXPECT(decrypts(stored(*after, sfConfidentialBalanceSpending), key, 60));
            BEAST_EXPECT(decrypts(stored(*after, sfIssuerEncryptedBalance), iss.issuer, 60));
            if (withAuditor)
            {
                BEAST_EXPECT(decrypts(stored(*after, sfAuditorEncryptedBalance), *iss.auditor, 60));
            }
            auto issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 260);
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 2'000);

            // The whole remaining balance, proved against the new version.
            env(convertBackJV(env, alice, key, iss, {.amount = 60, .balance = 60}));
            env.close();
            after = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(after && (*after)[sfMPTAmount] == 1'000);
            BEAST_EXPECT(after && decrypts(stored(*after, sfConfidentialBalanceSpending), key, 0));
            BEAST_EXPECT(
                after && decrypts(stored(*after, sfIssuerEncryptedBalance), iss.issuer, 0));
            issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 200);

            // Nothing is left to convert back.
            env(convertBackJV(env, alice, key, iss, {.amount = 1, .balance = 0}),
                Ter(tecBAD_PROOF));
        }

        // The version wraps from 2^32 - 1 to 0, and the proof binds 2^32 - 1.
        // The open-ledger edit is lost at the next close, so this comes last.
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob});
            fundConfidential(env, alice, bob, key, iss);
            modifyEntry(env, keylet::mptoken(iss.id, alice), [](SLE& sle) {
                sle.setFieldU32(sfConfidentialBalanceVersion, 0xFFFF'FFFF);
            });
            env(convertBackJV(env, alice, key, iss));
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 0);
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 60));
        }
    }

    // Auditor policy both ways, freeze before proofs, ticket and Batch
    // binding, and an identity remainder commitment.
    void
    testConvertBackBinding()
    {
        testcase("ConvertBack binding");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);

        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss =
                issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance | tfMPTCanLock, true);
            fundConfidential(env, alice, bob, key, iss);

            Issuance unaudited = iss;
            unaudited.auditor.reset();
            env(convertBackJV(env, alice, key, unaudited), Ter(tecNO_PERMISSION));
            {
                auto jv = convertBackJV(env, alice, key, iss);
                jv[sfAuditorEncryptedAmount.jsonName] = hex(elGamalEncrypt(
                    Scalar::fromUint64(41), Scalar::fromUint64(13), iss.auditor->pub));
                env(jv, Ter(tecBAD_PROOF));
            }

            // PC_b = m·G with rho = 0 makes PC_rem the identity, which no
            // range proof opens.
            {
                auto jv = convertBackJV(env, alice, key, iss, {.amount = 100});
                auto const sle = env.le(keylet::mptoken(iss.id, alice));
                if (!BEAST_EXPECT(sle))
                    return;
                auto const commitment = mulGenerator(Scalar::fromUint64(100));
                auto const ctx = transactionContextID(
                    ttCONFIDENTIAL_MPT_CONVERT_BACK,
                    alice.id(),
                    iss.id,
                    env.seq(alice),
                    alice.id(),
                    sle->getFieldU32(sfConfidentialBalanceVersion));
                auto const sigma = proveBalance(
                    {.key = key.pub,
                     .balance = *stored(*sle, sfConfidentialBalanceSpending),
                     .balanceCommitment = commitment},
                    Scalar::fromUint64(100),
                    Scalar{},
                    key.secret,
                    ctx);
                jv[sfBalanceCommitment.jsonName] = strHex(*commitment.bytes());
                jv[sfZKProof.jsonName] =
                    strHex(sigma) + jv[sfZKProof.jsonName].asString().substr(256);
                env(jv, Ter(tecBAD_PROOF));
            }

            // A ticketed ConvertBack binds its proofs to the ticket.
            std::uint32_t const ticket = env.seq(alice) + 1;
            env(ticket::create(alice, 2));
            env.close();
            {
                auto jv = convertBackJV(env, alice, key, iss, {.ticket = ticket});
                jv[sfZKProof.jsonName] = convertBackJV(env, alice, key, iss)[sfZKProof.jsonName];
                env(jv, Ter(tecBAD_PROOF));
            }
            env(convertBackJV(env, alice, key, iss, {.ticket = ticket + 1}));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 60));

            // Locks come before any proof or amount check; the held
            // transaction ends this ledger history.
            env(issuanceSetJV(gw, iss.id, tfMPTLock, alice));
            env.close();
            auto const xrp = env.balance(alice).value().xrp();
            auto const seq = env.seq(alice);
            env(convertBackJV(env, alice, key, iss, {.balance = 61}), Ter(terFROZEN));
            env(convertBackJV(env, alice, key, iss, {.amount = 301, .balance = 400}),
                Ter(terFROZEN));
            BEAST_EXPECT(env.balance(alice).value().xrp() == xrp);
            BEAST_EXPECT(env.seq(alice) == seq);
        }

        // Inner Batch ConvertBacks bind to their own sequence and roll back
        // with the batch.
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob});
            fundConfidential(env, alice, bob, key, iss);
            auto const base = env.current()->fees().base;
            auto const batchFee = base * 2 + base * 10 * 2;

            auto seq = env.seq(alice);
            env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
                batch::Inner(convertBackJV(env, alice, key, iss, {.sequence = seq + 1}), seq + 1),
                batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
            env.close();
            auto sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            BEAST_EXPECT((*sle)[sfMPTAmount] == 940);
            BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 3);
            BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 60));

            // A cancelled spending C1 in doApply rolls the whole batch back.
            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            auto const spendingR = r0 + r0 + Scalar::fromUint64(7) + r0 - Scalar::fromUint64(13);
            auto const before = sle->getFieldVL(sfConfidentialBalanceSpending);
            seq = env.seq(alice);
            env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
                batch::Inner(
                    convertBackJV(
                        env,
                        alice,
                        key,
                        iss,
                        {.amount = 10,
                         .balance = 60,
                         .randomness = spendingR,
                         .sequence = seq + 1}),
                    seq + 1),
                batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
            env.close();
            sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && sle->getFieldVL(sfConfidentialBalanceSpending) == before);
            BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 3);
            BEAST_EXPECT(env.seq(alice) == seq + 1);
        }
    }

    // After Convert(100, r1) and a merge, the spending balance has randomness
    // 2·r0 + r1 and the mirrors r0 + r1, all known to the holder. A blinding
    // factor equal to that randomness cancels C1; r = R + 60 / sk cancels the
    // C2 of a ConvertBack of 40 for whoever knows sk.
    void
    testConvertBackIdentity()
    {
        testcase("ConvertBack identity results");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const key(11);
        auto const r1 = Scalar::fromUint64(7);

        for (int target = 0; target < 5; ++target)
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, true);
            env(convertJV(env, alice, key, iss, {.amount = 100, .randomness = r1}));
            env(convertJV(env, bob, Key(21), iss, {.amount = 200}));
            env.close();
            env(mergeJV(env, alice, iss.id));
            env.close();

            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            auto const spendingR = r0 + r0 + r1;
            auto const mirrorR = r0 + r1;
            auto const cancelC2 = [&](Scalar const& randomness, Key const& k) {
                return randomness + Scalar::fromUint64(60) * k.secret.inverse();
            };
            std::array<Scalar, 5> const blinding{
                spendingR,
                mirrorR,
                cancelC2(spendingR, key),
                cancelC2(mirrorR, iss.issuer),
                cancelC2(mirrorR, *iss.auditor)};
            env(convertBackJV(env, alice, key, iss, {.randomness = blinding[target]}),
                Ter(tecBAD_PROOF));
            env.close();
            env(convertBackJV(env, alice, key, iss));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), key, 60));
        }
    }

    // alice (key 11) and bob (key 21) each convert and merge 100 and 200.
    static void
    fundSendParties(
        jtx::Env& env,
        jtx::Account const& alice,
        jtx::Account const& bob,
        Issuance const& iss)
    {
        env(convertJV(env, alice, Key(11), iss, {.amount = 100}));
        env(convertJV(env, bob, Key(21), iss, {.amount = 200}));
        env.close();
        env(mergeJV(env, alice, iss.id));
        env(mergeJV(env, bob, iss.id));
        env.close();
    }

    void
    testSendPreflight()
    {
        testcase("Send preflight");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);

        {
            Env env{*this, testableAmendments() - featureConfidentialTransfer};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            Issuance const iss{.id = makeMptID(1, gw)};
            env(sendJV(env, alice, ka, bob, kb, iss), Ter(temDISABLED));
        }
        // CredentialIDs needs the Credentials amendment.
        {
            Env env{*this, testableAmendments() - featureCredentials};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob});
            fundSendParties(env, alice, bob, iss);
            env(sendJV(env, alice, ka, bob, kb, iss),
                credentials::Ids({to_string(uint256{7})}),
                Ter(temDISABLED));
            env(sendJV(env, alice, ka, bob, kb, iss));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});
        fundSendParties(env, alice, bob, iss);

        // Section 8.3.1(2)-(3), and the issuer cannot receive (section A.10).
        env(sendJV(env, gw, ka, bob, kb, iss), Ter(temMALFORMED));
        env(sendJV(env, alice, ka, alice, ka, iss), Ter(temMALFORMED));
        env(sendJV(env, alice, ka, gw, kb, iss), Ter(temMALFORMED));
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[jss::Flags] = tfMPTLock;
            env(jv, Ter(temINVALID_FLAG));
        }

        // Section 8.3.1(4): 192 + 754 bytes.
        for (auto const size : {945, 947})
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            auto const proof = jv[sfZKProof.jsonName].asString();
            jv[sfZKProof.jsonName] = size == 945 ? proof.substr(0, 1890) : proof + "00";
            env(jv, Ter(temMALFORMED));
        }

        // Section 8.3.1(5): both commitments are valid points.
        for (SF_VL const* field : {&sfBalanceCommitment, &sfAmountCommitment})
        {
            for (auto const& bad : {std::string(64, '1'), "02" + std::string(64, '0')})
            {
                auto jv = sendJV(env, alice, ka, bob, kb, iss);
                jv[field->jsonName] = bad;
                env(jv, Ter(temMALFORMED));
            }
        }

        // Section 8.3.1(6)-(7): valid ciphertexts sharing one C1.
        auto const issAudited = [&] {
            auto copy = iss;
            copy.auditor.emplace(102);
            return copy;
        }();
        for (SF_VL const* field :
             {&sfSenderEncryptedAmount,
              &sfDestinationEncryptedAmount,
              &sfIssuerEncryptedAmount,
              &sfAuditorEncryptedAmount})
        {
            auto const good =
                sendJV(env, alice, ka, bob, kb, issAudited)[field->jsonName].asString();
            for (auto const& bad : {good.substr(0, 130), "04" + good.substr(2)})
            {
                auto jv = sendJV(env, alice, ka, bob, kb, issAudited);
                jv[field->jsonName] = bad;
                env(jv, Ter(temBAD_CIPHERTEXT));
            }
            if (field == &sfSenderEncryptedAmount)
                continue;
            // The same amount under a different C1.
            auto jv = sendJV(env, alice, ka, bob, kb, issAudited);
            jv[field->jsonName] = hex(elGamalEncrypt(
                Scalar::fromUint64(30),
                Scalar::fromUint64(24),
                mulGenerator(Scalar::fromUint64(5))));
            env(jv, Ter(temBAD_CIPHERTEXT));
        }

        // XLS-70 credential array checks.
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[sfCredentialIDs.jsonName] = json::ValueType::Array;
            env(jv, Ter(temMALFORMED));
        }

        // The underpaying transaction is held for the next ledger, so this
        // comes last.
        auto jv = sendJV(env, alice, ka, bob, kb, iss);
        jv[jss::Fee] = to_string(env.current()->fees().base * 10 - 1);
        env(jv, Ter(telINSUF_FEE_P));
    }

    void
    testSendPreclaim()
    {
        testcase("Send preclaim");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Account const dave("dave");
        Key const ka(11);
        Key const kb(21);
        Key const kc(31);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob, carol});
        fundSendParties(env, alice, bob, iss);

        {
            Issuance missing = iss;
            missing.id = makeMptID(999, gw);
            env(sendJV(env, alice, ka, bob, kb, missing), Ter(tecOBJECT_NOT_FOUND));
        }
        // Section 8.3.2(1): the destination account must exist.
        env(sendJV(env, alice, ka, dave, kb, iss), Ter(tecNO_TARGET));

        // Section 8.3.2(2)-(3): transferable, and confidential.
        {
            auto const locked =
                issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, false, true, 0);
            env(sendJV(env, alice, ka, bob, kb, locked), Ter(tecNO_AUTH));
            MPTTester const plain({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 10});
            Issuance const other{.id = plain.issuanceID()};
            env(sendJV(env, alice, ka, bob, kb, other), Ter(tecNO_PERMISSION));
            auto const noKeys =
                issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, false, false);
            env(sendJV(env, alice, ka, bob, kb, noKeys), Ter(tecNO_PERMISSION));
        }

        // Section 8.3.2(4): both parties hold initialized MPTokens.
        env(sendJV(env, alice, ka, carol, kc, iss), Ter(tecNO_PERMISSION));
        env(sendJV(env, carol, kc, alice, ka, iss), Ter(tecNO_PERMISSION));
        env.fund(XRP(10'000), dave);
        env.close();
        env(sendJV(env, alice, ka, dave, kb, iss), Ter(tecNO_PERMISSION));

        // The auditor ciphertext follows the issuance's auditor key.
        {
            Issuance extra = iss;
            extra.auditor.emplace(102);
            env(sendJV(env, alice, ka, bob, kb, extra), Ter(tecNO_PERMISSION));
        }

        // XLS-70: a credential that doesn't exist.
        env(sendJV(env, alice, ka, bob, kb, iss),
            credentials::Ids({to_string(uint256{7})}),
            Ter(tecBAD_CREDENTIALS));

        // Section 8.3.2(5): the sigma proof binds every ciphertext, both
        // commitments, the sender's balance and key, the destination and the
        // sender's version.
        env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 101}), Ter(tecBAD_PROOF));
        env(sendJV(env, alice, Key(12), bob, kb, iss), Ter(tecBAD_PROOF));
        env(sendJV(env, alice, ka, bob, Key(22), iss), Ter(tecBAD_PROOF));
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[sfDestinationEncryptedAmount.jsonName] =
                hex(elGamalEncrypt(Scalar::fromUint64(31), Scalar::fromUint64(23), kb.pub));
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[sfAmountCommitment.jsonName] =
                strHex(*pedersenCommit(Scalar::fromUint64(31), Scalar::fromUint64(23)).bytes());
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[sfBalanceCommitment.jsonName] =
                strHex(*pedersenCommit(Scalar::fromUint64(100), Scalar::fromUint64(30)).bytes());
            env(jv, Ter(tecBAD_PROOF));
        }
        for (auto const& [field, pk] :
             {std::pair{&sfSenderEncryptedAmount, ka.pub},
              std::pair{&sfIssuerEncryptedAmount, iss.issuer.pub}})
        {
            // Another amount under the same C1.
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            jv[field->jsonName] =
                hex(elGamalEncrypt(Scalar::fromUint64(31), Scalar::fromUint64(23), pk));
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            // PC_b = PC_m makes PC_rem the identity, which no range proof
            // opens.
            auto const range = strUnHex(
                sendJV(env, alice, ka, bob, kb, iss)[sfZKProof.jsonName].asString().substr(384));
            env(sendJV(
                    env,
                    alice,
                    ka,
                    bob,
                    kb,
                    iss,
                    {.amount = 100, .blinding = Scalar::fromUint64(23), .rangeProof = range}),
                Ter(tecBAD_PROOF));
        }
        {
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            if (!BEAST_EXPECT(sle))
                return;
            auto const version = sle->getFieldU32(sfConfidentialBalanceVersion);
            env(sendJV(env, alice, ka, bob, kb, iss, {.version = version + 1}), Ter(tecBAD_PROOF));
        }
        {
            // A proof for another destination.
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            auto const other = sendJV(env, alice, ka, carol, kb, iss);
            jv[sfZKProof.jsonName] = other[sfZKProof.jsonName];
            env(jv, Ter(tecBAD_PROOF));
        }
        {
            // A valid sigma proof spliced onto another transaction's range proof.
            auto jv = sendJV(env, alice, ka, bob, kb, iss);
            auto const other =
                sendJV(env, alice, ka, bob, kb, iss, {.blinding = Scalar::fromUint64(30)});
            jv[sfZKProof.jsonName] = jv[sfZKProof.jsonName].asString().substr(0, 384) +
                other[sfZKProof.jsonName].asString().substr(384);
            env(jv, Ter(tecBAD_PROOF));
        }
        // The remainder must be in range: b = 100 and m = 150.
        env(sendJV(env, alice, ka, bob, kb, iss, {.amount = 150}), Ter(tecBAD_PROOF));

        // Section 8.2 has no DestinationTag, but an account that requires
        // one still gets tecDST_TAG_NEEDED without it.
        env(fset(bob, asfRequireDest));
        env.close();
        env(sendJV(env, alice, ka, bob, kb, iss), Ter(tecDST_TAG_NEEDED));
        env(sendJV(env, alice, ka, bob, kb, iss), Dtag(7));
        env.close();
        auto const sle = env.le(keylet::mptoken(iss.id, bob));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), kb, 30));
    }

    void
    testSendAuthAndFreeze()
    {
        testcase("Send authorization and freeze");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);

        auto const setup = [&](Env& env) {
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(
                env,
                gw,
                {alice, bob},
                tfMPTCanHoldConfidentialBalance | tfMPTRequireAuth | tfMPTCanLock);
            fundSendParties(env, alice, bob, iss);
            return iss;
        };

        // terFROZEN is a retry code: the transaction is held and retried in
        // the next ledger, so each lock gets its own ledger history.
        for (int lock = 0; lock < 3; ++lock)
        {
            Env env{*this};
            auto const iss = setup(env);
            if (lock == 0)
                env(issuanceSetJV(gw, iss.id, tfMPTLock, alice));
            else if (lock == 1)
                env(issuanceSetJV(gw, iss.id, tfMPTLock, bob));
            else
                env(issuanceSetJV(gw, iss.id, tfMPTLock));
            env.close();
            env(sendJV(env, alice, ka, bob, kb, iss), Ter(terFROZEN));
            // Before any proof.
            env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 101}), Ter(terFROZEN));
        }

        // Both parties must be authorized.
        for (auto const& party : {alice, bob})
        {
            Env env{*this};
            auto const iss = setup(env);
            json::Value jv;
            jv[jss::TransactionType] = jss::MPTokenAuthorize;
            jv[jss::Account] = gw.human();
            jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
            jv[sfHolder.jsonName] = party.human();
            jv[jss::Flags] = tfMPTUnauthorize;
            env(jv);
            env.close();
            env(sendJV(env, alice, ka, bob, kb, iss), Ter(tecNO_AUTH));
            env.close();
            jv[jss::Flags] = 0;
            env(jv);
            env.close();
            env(sendJV(env, alice, ka, bob, kb, iss));
        }
    }

    // The auditor policy, ticket binding, and inner Batch Sends.
    void
    testSendBinding()
    {
        testcase("Send binding");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);

        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, true);
            fundSendParties(env, alice, bob, iss);

            Issuance unaudited = iss;
            unaudited.auditor.reset();
            env(sendJV(env, alice, ka, bob, kb, unaudited), Ter(tecNO_PERMISSION));
            {
                auto jv = sendJV(env, alice, ka, bob, kb, iss);
                jv[sfAuditorEncryptedAmount.jsonName] = hex(elGamalEncrypt(
                    Scalar::fromUint64(31), Scalar::fromUint64(23), iss.auditor->pub));
                env(jv, Ter(tecBAD_PROOF));
            }

            std::uint32_t const ticket = env.seq(alice) + 1;
            env(ticket::create(alice, 2));
            env.close();
            {
                auto jv = sendJV(env, alice, ka, bob, kb, iss, {.ticket = ticket});
                jv[sfZKProof.jsonName] = sendJV(env, alice, ka, bob, kb, iss)[sfZKProof.jsonName];
                env(jv, Ter(tecBAD_PROOF));
            }
            env(sendJV(env, alice, ka, bob, kb, iss, {.ticket = ticket + 1}));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, bob));
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), kb, 30));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});
        fundSendParties(env, alice, bob, iss);
        auto const base = env.current()->fees().base;
        auto const batchFee = base * 2 + base * 10 * 2;

        // The inner Send binds its proofs to its own sequence.
        auto seq = env.seq(alice);
        env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
            batch::Inner(sendJV(env, alice, ka, bob, kb, iss, {.sequence = seq + 1}), seq + 1),
            batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
        env.close();
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(sle))
            return;
        BEAST_EXPECT((*sle)[sfConfidentialBalanceVersion] == 3);
        BEAST_EXPECT(decrypts(stored(*sle, sfConfidentialBalanceSpending), ka, 70));
        BEAST_EXPECT(decrypts(
            stored(*env.le(keylet::mptoken(iss.id, bob)), sfConfidentialBalanceInbox), kb, 30));

        // A cancelled sender debit rolls the whole batch back.
        auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
        auto const spendingR = r0 + r0 + Scalar::fromUint64(7) + r0 - Scalar::fromUint64(23);
        auto const before = sle->getFieldVL(sfConfidentialBalanceSpending);
        seq = env.seq(alice);
        env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
            batch::Inner(
                sendJV(
                    env,
                    alice,
                    ka,
                    bob,
                    kb,
                    iss,
                    {.amount = 10, .balance = 70, .randomness = spendingR, .sequence = seq + 1}),
                seq + 1),
            batch::Inner(mergeJV(env, alice, iss.id), seq + 2));
        env.close();
        sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && sle->getFieldVL(sfConfidentialBalanceSpending) == before);
        BEAST_EXPECT(env.seq(alice) == seq + 1);
    }

    // Section 8.3.2.1: deposit authorization and credentials.
    void
    testSendDepositAuth()
    {
        testcase("Send deposit authorization");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const ka(11);
        Key const kb(21);
        std::string const credType = "KYC";

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});
        fundSendParties(env, alice, bob, iss);

        env(fset(bob, asfDepositAuth));
        env.close();
        env(sendJV(env, alice, ka, bob, kb, iss), Ter(tecNO_PERMISSION));
        env.close();
        env(deposit::auth(bob, alice));
        env.close();
        env(sendJV(env, alice, ka, bob, kb, iss));
        env.close();
        env(deposit::unauth(bob, alice));
        env(deposit::authCredentials(bob, {{carol, credType}}));
        env.close();
        env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 70}), Ter(tecNO_PERMISSION));
        env.close();

        // An accepted credential of the authorized type.
        env(credentials::create(alice, carol, credType));
        env.close();
        env(credentials::accept(alice, carol, credType));
        env.close();
        auto const credIdx =
            credentials::ledgerEntry(env, alice, carol, credType)[jss::result][jss::index]
                .asString();
        env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 70}), credentials::Ids({credIdx}));
        env.close();
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), ka, 40));

        // Expired credentials are deleted and the Send fails.
        env(credentials::deleteCred(alice, alice, carol, credType));
        {
            auto jv = credentials::create(alice, carol, credType);
            jv[sfExpiration.jsonName] =
                env.current()->header().parentCloseTime.time_since_epoch().count() + 20;
            env(jv);
        }
        env.close();
        env(credentials::accept(alice, carol, credType));
        env.close();
        auto const expiredIdx =
            credentials::ledgerEntry(env, alice, carol, credType)[jss::result][jss::index]
                .asString();
        for (int i = 0; i < 5; ++i)
            env.close();
        // An expired credential of an unauthorized type fails authorization
        // first: tecNO_PERMISSION, and it is not removed (section
        // 8.3.2.1(4)).
        std::string const otherType = "AML";
        {
            auto jv = credentials::create(alice, carol, otherType);
            jv[sfExpiration.jsonName] =
                env.current()->header().parentCloseTime.time_since_epoch().count() + 20;
            env(jv);
        }
        env.close();
        env(credentials::accept(alice, carol, otherType));
        env.close();
        auto const otherIdx =
            credentials::ledgerEntry(env, alice, carol, otherType)[jss::result][jss::index]
                .asString();
        for (int i = 0; i < 5; ++i)
            env.close();
        env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 40}),
            credentials::Ids({otherIdx}),
            Ter(tecNO_PERMISSION));
        env.close();
        BEAST_EXPECT(env.le(credentials::keylet(alice, carol, otherType)));

        // An expired credential of the authorized type is removed.
        env(sendJV(env, alice, ka, bob, kb, iss, {.balance = 40}),
            credentials::Ids({expiredIdx}),
            Ter(tecEXPIRED));
        env.close();
        BEAST_EXPECT(!env.le(credentials::keylet(alice, carol, credType)));
        sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), ka, 40));
    }

    void
    testSendApply()
    {
        testcase("Send apply");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);

        for (bool const withAuditor : {false, true})
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss =
                issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, withAuditor);
            fundSendParties(env, alice, bob, iss);

            auto const senderBefore = env.le(keylet::mptoken(iss.id, alice));
            auto const receiverBefore = env.le(keylet::mptoken(iss.id, bob));
            auto const jv = sendJV(env, alice, ka, bob, kb, iss, {.amount = 30});
            env(jv);
            env.close();
            auto const senderAfter = env.le(keylet::mptoken(iss.id, alice));
            auto const receiverAfter = env.le(keylet::mptoken(iss.id, bob));
            if (!BEAST_EXPECT(senderBefore && receiverBefore && senderAfter && receiverAfter))
                return;

            // Updated spec eq. (8)-(13).
            auto const m = Scalar::fromUint64(30);
            auto const r = Scalar::fromUint64(23);
            auto const e = Scalar::fromBytes(
                makeSlice(strUnHex(jv[sfZKProof.jsonName].asString().substr(0, 64)).value()));
            if (!BEAST_EXPECT(e))
                return;
            auto const rerandomize = [&](Point const& pk) {
                return elGamalEncrypt(Scalar{}, *e, pk);
            };
            BEAST_EXPECT(
                stored(*senderAfter, sfConfidentialBalanceSpending) ==
                *stored(*senderBefore, sfConfidentialBalanceSpending) -
                    elGamalEncrypt(m, r, ka.pub));
            BEAST_EXPECT(
                (*senderAfter)[sfConfidentialBalanceVersion] ==
                (*senderBefore)[sfConfidentialBalanceVersion] + 1);
            BEAST_EXPECT(
                stored(*receiverAfter, sfConfidentialBalanceInbox) ==
                *stored(*receiverBefore, sfConfidentialBalanceInbox) +
                    elGamalEncrypt(m, r, kb.pub) + rerandomize(kb.pub));
            BEAST_EXPECT(
                stored(*receiverAfter, sfIssuerEncryptedBalance) ==
                *stored(*receiverBefore, sfIssuerEncryptedBalance) +
                    elGamalEncrypt(m, r, iss.issuer.pub) + rerandomize(iss.issuer.pub));
            BEAST_EXPECT(
                (*receiverAfter)[sfConfidentialBalanceVersion] ==
                (*receiverBefore)[sfConfidentialBalanceVersion]);
            BEAST_EXPECT(
                receiverAfter->getFieldVL(sfConfidentialBalanceSpending) ==
                receiverBefore->getFieldVL(sfConfidentialBalanceSpending));
            BEAST_EXPECT(decrypts(stored(*senderAfter, sfConfidentialBalanceSpending), ka, 70));
            BEAST_EXPECT(decrypts(stored(*senderAfter, sfIssuerEncryptedBalance), iss.issuer, 70));
            BEAST_EXPECT(decrypts(stored(*receiverAfter, sfConfidentialBalanceInbox), kb, 30));
            BEAST_EXPECT(
                decrypts(stored(*receiverAfter, sfIssuerEncryptedBalance), iss.issuer, 230));
            if (withAuditor)
            {
                BEAST_EXPECT(
                    decrypts(stored(*senderAfter, sfAuditorEncryptedBalance), *iss.auditor, 70));
                BEAST_EXPECT(
                    decrypts(stored(*receiverAfter, sfAuditorEncryptedBalance), *iss.auditor, 230));
            }
            BEAST_EXPECT((*senderAfter)[sfMPTAmount] == 900);
            BEAST_EXPECT((*receiverAfter)[sfMPTAmount] == 800);
            auto const issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 300);
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 2'000);

            // The receiver merges and sends back; alice spends everything.
            env(mergeJV(env, bob, iss.id));
            env.close();
            env(sendJV(env, bob, kb, alice, ka, iss, {.amount = 230, .balance = 230}));
            env(sendJV(env, alice, ka, bob, kb, iss, {.amount = 70, .balance = 70}));
            env.close();
            env(mergeJV(env, alice, iss.id));
            env(mergeJV(env, bob, iss.id));
            env.close();
            auto const a = env.le(keylet::mptoken(iss.id, alice));
            auto const b = env.le(keylet::mptoken(iss.id, bob));
            BEAST_EXPECT(a && decrypts(stored(*a, sfConfidentialBalanceSpending), ka, 230));
            BEAST_EXPECT(b && decrypts(stored(*b, sfConfidentialBalanceSpending), kb, 70));
            BEAST_EXPECT(a && decrypts(stored(*a, sfIssuerEncryptedBalance), iss.issuer, 230));
            BEAST_EXPECT(b && decrypts(stored(*b, sfIssuerEncryptedBalance), iss.issuer, 70));

            // A zero amount is allowed; it only re-randomizes.
            env(sendJV(env, alice, ka, bob, kb, iss, {.amount = 0, .balance = 230}));
            env.close();
            BEAST_EXPECT(decrypts(
                stored(*env.le(keylet::mptoken(iss.id, bob)), sfConfidentialBalanceInbox), kb, 0));
        }

        // The sender's version wraps from 2^32 - 1 to 0, and the proof binds
        // 2^32 - 1. The open-ledger edit is lost at the next close, so this
        // comes last.
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob});
            fundSendParties(env, alice, bob, iss);
            modifyEntry(env, keylet::mptoken(iss.id, alice), [](SLE& sle) {
                sle.setFieldU32(sfConfidentialBalanceVersion, 0xFFFF'FFFF);
            });
            env(sendJV(env, alice, ka, bob, kb, iss));
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && (*sle)[sfConfidentialBalanceVersion] == 0);
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), ka, 70));
        }
    }

    // The sender knows its own randomness and can cancel its debits; those
    // Sends fail. After Convert(100, r1) and a merge, the spending balance has
    // randomness 2·r0 + r1 and the mirrors r0 + r1; r = R + 70 / sk cancels
    // the C2 of a Send of 30 for whoever knows sk.
    void
    testSendIdentity()
    {
        testcase("Send identity results");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);
        auto const r1 = Scalar::fromUint64(7);

        for (int target = 0; target < 5; ++target)
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(env, gw, {alice, bob}, tfMPTCanHoldConfidentialBalance, true);
            env(convertJV(env, alice, ka, iss, {.amount = 100, .randomness = r1}));
            env(convertJV(env, bob, kb, iss, {.amount = 200}));
            env.close();
            env(mergeJV(env, alice, iss.id));
            env.close();

            auto const r0 = encryptedZeroRandomness(alice.id(), iss.id);
            auto const spendingR = r0 + r0 + r1;
            auto const mirrorR = r0 + r1;
            auto const cancelC2 = [&](Scalar const& randomness, Key const& k) {
                return randomness + Scalar::fromUint64(70) * k.secret.inverse();
            };
            std::array<Scalar, 5> const blinding{
                spendingR,
                mirrorR,
                cancelC2(spendingR, ka),
                cancelC2(mirrorR, iss.issuer),
                cancelC2(mirrorR, *iss.auditor)};
            env(sendJV(env, alice, ka, bob, kb, iss, {.randomness = blinding[target]}),
                Ter(tecBAD_PROOF));
            env.close();
            env(sendJV(env, alice, ka, bob, kb, iss));
            env.close();
            auto const sle = env.le(keylet::mptoken(iss.id, alice));
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceSpending), ka, 70));
        }
    }

    void
    testSendDelegation()
    {
        testcase("Send delegation");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const ka(11);
        Key const kb(21);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob});
        fundSendParties(env, alice, bob, iss);
        env(delegate::set(alice, carol, {"ConfidentialMPTSend"}));
        env.close();

        // The proof needs alice's secret key; carol only submits and pays.
        auto const carolXrp = env.balance(carol).value().xrp();
        env(sendJV(env, alice, ka, bob, kb, iss), delegate::As(carol));
        env.close();
        BEAST_EXPECT(
            env.balance(carol).value().xrp() == carolXrp - env.current()->fees().base * 10);
        auto const sle = env.le(keylet::mptoken(iss.id, bob));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), kb, 30));
    }

    // The issuer's clawback of `amount` from holder, proved against the
    // holder's on-ledger issuer mirror with the issuer's secret key.
    static json::Value
    clawbackJV(
        jtx::Env& env,
        jtx::Account const& issuer,
        jtx::Account const& holder,
        Issuance const& iss,
        std::uint64_t amount,
        ClawbackArgs const& args = {})
    {
        auto const sle = env.le(keylet::mptoken(iss.id, holder));
        auto const mirror = sle ? stored(*sle, sfIssuerEncryptedBalance) : std::nullopt;
        auto const key = args.signingKey ? Key(*args.signingKey) : iss.issuer;
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTClawback;
        jv[jss::Account] = issuer.human();
        jv[sfHolder.jsonName] = holder.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
        jv[sfMPTAmount.jsonName] = std::to_string(amount);
        std::uint32_t sequence = args.sequence.value_or(env.seq(issuer));
        if (args.ticket)
        {
            jv[jss::Sequence] = 0;
            jv[sfTicketSequence.jsonName] = *args.ticket;
            sequence = *args.ticket;
        }
        auto const ctx = transactionContextID(
            ttCONFIDENTIAL_MPT_CLAWBACK, issuer.id(), iss.id, sequence, holder.id(), 0);
        // An uninitialized holder gets a proof over a stand-in mirror.
        jv[sfZKProof.jsonName] = strHex(proveClawback(
            key.pub,
            mirror.value_or(elGamalEncrypt(Scalar::fromUint64(1), Scalar::fromUint64(1), key.pub)),
            Scalar::fromUint64(amount),
            key.secret,
            ctx));
        jv[jss::Fee] = confidentialFee(env);
        return jv;
    }

    static constexpr std::uint32_t kClawable = tfMPTCanHoldConfidentialBalance | tfMPTCanClawback;

    void
    testClawbackPreflight()
    {
        testcase("Clawback preflight");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");

        {
            Env env{*this, testableAmendments() - featureConfidentialTransfer};
            env.fund(XRP(10'000), gw, alice);
            env.close();
            Issuance const iss{.id = makeMptID(1, gw)};
            env(clawbackJV(env, gw, alice, iss, 10), Ter(temDISABLED));
        }

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob);
        env.close();
        auto const iss = issue(env, gw, {alice, bob}, kClawable);
        fundSendParties(env, alice, bob, iss);

        // Section 11.3.1(2)-(5).
        env(clawbackJV(env, alice, bob, iss, 200), Ter(temMALFORMED));
        env(clawbackJV(env, gw, gw, iss, 100), Ter(temMALFORMED));
        for (auto const size : {63, 65})
        {
            auto jv = clawbackJV(env, gw, alice, iss, 100);
            auto const proof = jv[sfZKProof.jsonName].asString();
            jv[sfZKProof.jsonName] = size == 63 ? proof.substr(0, 126) : proof + "00";
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = clawbackJV(env, gw, alice, iss, 100);
            jv[sfMPTAmount.jsonName] = "0";
            env(jv, Ter(temBAD_AMOUNT));
            jv[sfMPTAmount.jsonName] = std::to_string(kMaxMpTokenAmount + 1);
            env(jv, Ter(temBAD_AMOUNT));
        }
        {
            auto jv = clawbackJV(env, gw, alice, iss, 100);
            jv[jss::Flags] = tfMPTLock;
            env(jv, Ter(temINVALID_FLAG));
        }

        // The underpaying transaction is held for the next ledger, so this
        // comes last.
        auto jv = clawbackJV(env, gw, alice, iss, 100);
        jv[jss::Fee] = to_string(env.current()->fees().base * 10 - 1);
        env(jv, Ter(telINSUF_FEE_P));
    }

    void
    testClawbackPreclaim()
    {
        testcase("Clawback preclaim");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Account const dave("dave");

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob, carol}, kClawable);
        fundSendParties(env, alice, bob, iss);

        // Section 11.3.2, in order.
        env(clawbackJV(env, gw, dave, iss, 100), Ter(tecNO_TARGET));
        {
            Issuance missing = iss;
            missing.id = makeMptID(999, gw);
            env(clawbackJV(env, gw, alice, missing, 100), Ter(tecOBJECT_NOT_FOUND));
        }
        env.fund(XRP(10'000), dave);
        env.close();
        env(clawbackJV(env, gw, dave, iss, 100), Ter(tecOBJECT_NOT_FOUND));
        {
            auto const noClawback = issue(env, gw, {alice});
            env(convertJV(env, alice, Key(11), noClawback, {.amount = 10}));
            env.close();
            env(clawbackJV(env, gw, alice, noClawback, 10), Ter(tecNO_PERMISSION));
            auto const noKeys = issue(env, gw, {alice}, kClawable, false, false);
            env(clawbackJV(env, gw, alice, noKeys, 10), Ter(tecNO_PERMISSION));
        }
        // Carol never converted, so she has no issuer mirror.
        env(clawbackJV(env, gw, carol, iss, 100), Ter(tecNO_PERMISSION));
        env(clawbackJV(env, gw, alice, iss, 301), Ter(tecINSUFFICIENT_FUNDS));

        // Section 11.3.2(7): the proof opens the mirror to exactly MPTAmount,
        // with the issuer key, for this holder.
        env(clawbackJV(env, gw, alice, iss, 99), Ter(tecBAD_PROOF));
        env(clawbackJV(env, gw, alice, iss, 100, {.signingKey = 103}), Ter(tecBAD_PROOF));
        {
            // Bound to the issuer's sequence.
            auto const early = clawbackJV(env, gw, alice, iss, 100);
            env(noop(gw));
            env(early, Ter(tecBAD_PROOF));
        }
        {
            // A proof for another holder does not transfer.
            auto jv = clawbackJV(env, gw, bob, iss, 200);
            jv[sfZKProof.jsonName] = clawbackJV(env, gw, alice, iss, 100)[sfZKProof.jsonName];
            env(jv, Ter(tecBAD_PROOF));
        }
        env(clawbackJV(env, gw, alice, iss, 100));
    }

    void
    testClawbackApply()
    {
        testcase("Clawback apply");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Key const ka(11);
        Key const kb(21);

        for (bool const withAuditor : {false, true})
        {
            Env env{*this};
            env.fund(XRP(10'000), gw, alice, bob);
            env.close();
            auto const iss = issue(
                env, gw, {alice, bob}, kClawable | tfMPTCanLock | tfMPTRequireAuth, withAuditor);
            fundSendParties(env, alice, bob, iss);

            // Bob's mirror covers spending (200) and inbox (30).
            env(sendJV(env, alice, ka, bob, kb, iss, {.amount = 30}));
            env.close();

            // The issuer may claw back from a locked, unauthorized holder.
            env(issuanceSetJV(gw, iss.id, tfMPTLock, bob));
            {
                json::Value jv;
                jv[jss::TransactionType] = jss::MPTokenAuthorize;
                jv[jss::Account] = gw.human();
                jv[sfMPTokenIssuanceID.jsonName] = to_string(iss.id);
                jv[sfHolder.jsonName] = bob.human();
                jv[jss::Flags] = tfMPTUnauthorize;
                env(jv);
            }
            env.close();

            auto const before = env.le(keylet::mptoken(iss.id, bob));
            env(clawbackJV(env, gw, bob, iss, 230));
            env.close();
            auto const after = env.le(keylet::mptoken(iss.id, bob));
            if (!BEAST_EXPECT(before && after))
                return;

            // Section 11.4 and updated spec eq. (63)-(68).
            BEAST_EXPECT(
                stored(*after, sfConfidentialBalanceSpending) ==
                encryptedZero(bob.id(), iss.id, kb.pub));
            BEAST_EXPECT(
                stored(*after, sfConfidentialBalanceInbox) ==
                encryptedZero(bob.id(), iss.id, kb.pub));
            BEAST_EXPECT(
                stored(*after, sfIssuerEncryptedBalance) ==
                encryptedZero(bob.id(), iss.id, iss.issuer.pub));
            BEAST_EXPECT(after->isFieldPresent(sfAuditorEncryptedBalance) == withAuditor);
            if (withAuditor)
            {
                BEAST_EXPECT(
                    stored(*after, sfAuditorEncryptedBalance) ==
                    encryptedZero(bob.id(), iss.id, iss.auditor->pub));
            }
            BEAST_EXPECT(
                (*after)[sfConfidentialBalanceVersion] ==
                (*before)[sfConfidentialBalanceVersion] + 1);
            BEAST_EXPECT(
                after->getFieldVL(sfHolderEncryptionKey) ==
                before->getFieldVL(sfHolderEncryptionKey));
            BEAST_EXPECT((*after)[sfMPTAmount] == 800);
            auto const issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 70);
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 1'770);

            // Clawing back an emptied holder fails: the mirror encrypts 0.
            env(clawbackJV(env, gw, bob, iss, 1), Ter(tecBAD_PROOF));
        }
    }

    // Updated spec section 5.6: the proof is not bound to the version, so a
    // holder cannot invalidate a prepared clawback with a merge; changing the
    // mirror (a Send) does.
    void
    testClawbackPrepared()
    {
        testcase("Clawback prepared ahead");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Key const ka(11);
        Key const kb(21);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice, bob, carol);
        env.close();
        auto const iss = issue(env, gw, {alice, bob}, kClawable);
        fundSendParties(env, alice, bob, iss);

        auto const prepared = clawbackJV(env, gw, alice, iss, 100);
        env(mergeJV(env, alice, iss.id));
        env.close();
        env(prepared);
        env.close();
        auto sle = env.le(keylet::mptoken(iss.id, alice));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, 0));

        auto const stale = clawbackJV(env, gw, bob, iss, 200);
        env(sendJV(env, bob, kb, alice, ka, iss, {.amount = 50, .balance = 200}));
        env.close();
        env(stale, Ter(tecBAD_PROOF));
        env.close();

        // The holder keeps its key and can use its confidential balance again;
        // a delegate of the issuer can claw back (section 5.5).
        env(delegate::set(gw, carol, {"ConfidentialMPTClawback"}));
        env.close();
        env(clawbackJV(env, gw, bob, iss, 150), delegate::As(carol));
        env.close();
        sle = env.le(keylet::mptoken(iss.id, bob));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, 0));
        env(convertJV(env, bob, kb, iss, {.amount = 10, .registerKey = false}));
        env.close();
        sle = env.le(keylet::mptoken(iss.id, bob));
        BEAST_EXPECT(sle && decrypts(stored(*sle, sfConfidentialBalanceInbox), kb, 10));
        auto const issuance = env.le(keylet::mptIssuance(iss.id));
        BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 60);
    }

    // Tickets, a global lock, Batch, multisigned fees, delegation without
    // permission, and locks stopping a holder's balance from changing under a
    // prepared clawback.
    void
    testClawbackBinding()
    {
        testcase("Clawback binding");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Account const bob("bob");
        Account const carol("carol");
        Account const dan("dan");
        Key const ka(11);
        Key const kb(21);

        auto const setup = [&](Env& env) {
            env.fund(XRP(10'000), gw, alice, bob, carol, dan);
            env.close();
            auto const iss = issue(env, gw, {alice, bob}, kClawable | tfMPTCanLock);
            fundSendParties(env, alice, bob, iss);
            return iss;
        };

        {
            Env env{*this};
            auto const iss = setup(env);

            // A ticketed clawback binds its proof to the ticket.
            std::uint32_t const ticket = env.seq(gw) + 1;
            env(ticket::create(gw, 2));
            env.close();
            {
                auto jv = clawbackJV(env, gw, alice, iss, 100, {.ticket = ticket});
                jv[sfZKProof.jsonName] = clawbackJV(env, gw, alice, iss, 100)[sfZKProof.jsonName];
                env(jv, Ter(tecBAD_PROOF));
            }
            env(clawbackJV(env, gw, alice, iss, 100, {.ticket = ticket + 1}));
            env.close();

            // Under a global lock, as an inner Batch transaction paying its
            // ten base fees.
            env(issuanceSetJV(gw, iss.id, tfMPTLock));
            env.close();
            auto const base = env.current()->fees().base;
            auto const seq = env.seq(gw);
            env(batch::outer(gw, seq, base * 2 + base * 10 + base, tfAllOrNothing),
                batch::Inner(clawbackJV(env, gw, bob, iss, 200, {.sequence = seq + 1}), seq + 1),
                batch::Inner(issuanceSetJV(gw, iss.id, tfMPTUnlock), seq + 2));
            env.close();
            auto issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 0);
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 1'700);
            BEAST_EXPECT(issuance && !issuance->isFlag(lsfMPTLocked));

            // Each multisigner adds one base fee.
            env(convertJV(env, bob, kb, iss, {.amount = 10, .registerKey = false}));
            env(signers(gw, 2, {{carol, 1}, {dan, 1}}));
            env.close();
            auto jv = clawbackJV(env, gw, bob, iss, 10);
            jv[jss::Fee] = to_string(base * 12);
            env(jv, Msig(carol, dan));
            env.close();
            issuance = env.le(keylet::mptIssuance(iss.id));
            BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 1'690);
            // The underpaying transaction is held for the next ledger, so
            // this ends the history.
            env(convertJV(env, bob, kb, iss, {.amount = 10, .registerKey = false}));
            env.close();
            jv = clawbackJV(env, gw, bob, iss, 10);
            jv[jss::Fee] = to_string(base * 12 - 1);
            env(jv, Msig(carol, dan), Ter(telINSUF_FEE_P));
        }

        // A delegate needs the permission.
        {
            Env env{*this};
            auto const iss = setup(env);
            env(clawbackJV(env, gw, alice, iss, 100),
                delegate::As(carol),
                Ter(terNO_DELEGATE_PERMISSION));
        }

        // Once the holder is locked, neither it nor anyone else can change
        // its mirror, so a prepared clawback stays valid.
        {
            Env env{*this};
            auto const iss = setup(env);
            env(issuanceSetJV(gw, iss.id, tfMPTLock, bob));
            env.close();
            auto const prepared = clawbackJV(env, gw, bob, iss, 200);
            env(sendJV(env, alice, ka, bob, kb, iss), Ter(terFROZEN));
            env(sendJV(env, bob, kb, alice, ka, iss, {.balance = 200}), Ter(terFROZEN));
            env(convertJV(env, bob, kb, iss, {.amount = 5, .registerKey = false}), Ter(tecLOCKED));
            env(prepared);
            auto const sle = env.le(keylet::mptoken(iss.id, bob));
            BEAST_EXPECT(sle && decrypts(stored(*sle, sfIssuerEncryptedBalance), iss.issuer, 0));
        }
    }

    // A public Clawback only reaches the public balance: OA falls by it, COA
    // and the confidential state are untouched, and the confidential part
    // needs a confidential clawback.
    void
    testPublicClawback()
    {
        testcase("Public clawback of a confidential holder");
        using namespace jtx;

        Account const gw("gw");
        Account const alice("alice");
        Key const ka(11);

        Env env{*this};
        env.fund(XRP(10'000), gw, alice);
        env.close();
        auto const iss = issue(env, gw, {alice}, kClawable);
        env(convertJV(env, alice, ka, iss, {.amount = 600}));
        env.close();

        auto const before = env.le(keylet::mptoken(iss.id, alice));
        MPT const mpt("MPT", iss.id);
        env(claw(gw, mpt(1'000), alice));
        env.close();
        auto const after = env.le(keylet::mptoken(iss.id, alice));
        if (!BEAST_EXPECT(before && after))
            return;
        BEAST_EXPECT((*after)[sfMPTAmount] == 0);
        for (SField const* field : std::initializer_list<SField const*>{
                 &sfHolderEncryptionKey,
                 &sfConfidentialBalanceSpending,
                 &sfConfidentialBalanceInbox,
                 &sfIssuerEncryptedBalance,
                 &sfConfidentialBalanceVersion})
        {
            BEAST_EXPECT(before->peekAtField(*field).isEquivalent(after->peekAtField(*field)));
        }
        auto issuance = env.le(keylet::mptIssuance(iss.id));
        BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 600);
        BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 600);

        env(clawbackJV(env, gw, alice, iss, 600));
        env.close();
        issuance = env.le(keylet::mptIssuance(iss.id));
        BEAST_EXPECT(issuance && (*issuance)[sfOutstandingAmount] == 0);
        BEAST_EXPECT(issuance && (*issuance)[sfConfidentialOutstandingAmount] == 0);
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
        check.operator()<ConfidentialMPTConvertBack>(ttCONFIDENTIAL_MPT_CONVERT_BACK);
        check.operator()<ConfidentialMPTSend>(ttCONFIDENTIAL_MPT_SEND);
        check.operator()<ConfidentialMPTClawback>(ttCONFIDENTIAL_MPT_CLAWBACK);
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
        testMergeInboxAudited();
        testRepeatedMerges();
        testConvertEscrowed();
        testBatch();
        testDelegation();
        testMultisignFee();
        testConvertBackPreflight();
        testConvertBackPreclaim();
        testConvertBackAuthAndFreeze();
        testConvertBackApply();
        testConvertBackIdentity();
        testConvertBackBinding();
        testSendPreflight();
        testSendPreclaim();
        testSendAuthAndFreeze();
        testSendDepositAuth();
        testSendApply();
        testSendIdentity();
        testSendDelegation();
        testSendBinding();
        testClawbackPreflight();
        testClawbackPreclaim();
        testClawbackApply();
        testClawbackPrepared();
        testClawbackBinding();
        testPublicClawback();
        testTransactionInvariants();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, app, xrpl);

}  // namespace xrpl::test
