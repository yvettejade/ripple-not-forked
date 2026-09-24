#include <xrpl/basics/Blob.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/Serializer.h>
#include <xrpl/protocol/UintTypes.h>

#include <cstdint>
#include <exception>
#include <limits>
#include <memory>

namespace xrpl {

class ConfidentialMPTFormats_test : public beast::unit_test::Suite
{
    static AccountID
    account(std::uint8_t b)
    {
        AccountID id;
        id.data()[0] = b;
        return id;
    }

    static std::shared_ptr<STLedgerEntry>
    roundTrip(STLedgerEntry const& sle)
    {
        Serializer s;
        sle.add(s);
        return std::make_shared<STLedgerEntry>(SerialIter{s.slice()}, sle.key());
    }

    void
    testAmendment()
    {
        testcase("Amendment");

        auto const f = getRegisteredFeature("ConfidentialTransfer");
        BEAST_EXPECT(f && *f == featureConfidentialTransfer);
        BEAST_EXPECT(featureToName(featureConfidentialTransfer) == "ConfidentialTransfer");
        // Not supported until the confidential transactors are implemented.
        BEAST_EXPECT(!detail::supportedAmendments().contains("ConfidentialTransfer"));
    }

    void
    testIssuanceFields()
    {
        testcase("MPTokenIssuance fields");

        auto const issuer = account(1);
        auto const id = makeMptID(7, issuer);
        STLedgerEntry sle(keylet::mptIssuance(id));
        sle[sfIssuer] = issuer;
        sle[sfSequence] = 7;
        sle[sfOwnerNode] = 0;
        sle[sfOutstandingAmount] = 1'000'000;
        sle[sfPreviousTxnID] = uint256{};
        sle[sfPreviousTxnLgrSeq] = 1;
        sle[sfFlags] = lsfMPTCanHoldConfidentialBalance;
        sle[sfImmutableFlags] = lsifMPTCanHoldConfidentialBalance;
        sle[sfConfidentialOutstandingAmount] = 500'000;
        Blob const issuerKey(33, 0x02);
        Blob const auditorKey(33, 0x03);
        sle.setFieldVL(sfIssuerEncryptionKey, issuerKey);
        sle.setFieldVL(sfAuditorEncryptionKey, auditorKey);

        auto const copy = roundTrip(sle);
        BEAST_EXPECT(copy->getFlags() == lsfMPTCanHoldConfidentialBalance);
        BEAST_EXPECT((*copy)[sfImmutableFlags] == lsifMPTCanHoldConfidentialBalance);
        BEAST_EXPECT((*copy)[sfConfidentialOutstandingAmount] == 500'000);
        BEAST_EXPECT(copy->getFieldVL(sfIssuerEncryptionKey) == issuerKey);
        BEAST_EXPECT(copy->getFieldVL(sfAuditorEncryptionKey) == auditorKey);

        // UINT64 amounts render as base-ten strings, like OutstandingAmount.
        auto const json = copy->getJson(JsonOptions::Values::None);
        BEAST_EXPECT(json[sfConfidentialOutstandingAmount.jsonName] == "500000");
        BEAST_EXPECT(json[sfOutstandingAmount.jsonName] == "1000000");

        // Both new integers are soeDEFAULT: assigning zero through the proxy
        // removes them, and an issuance without them round-trips.
        sle[sfConfidentialOutstandingAmount] = 0;
        sle[sfImmutableFlags] = 0;
        BEAST_EXPECT(!sle.isFieldPresent(sfConfidentialOutstandingAmount));
        BEAST_EXPECT(!sle.isFieldPresent(sfImmutableFlags));
        BEAST_EXPECT(sle[sfConfidentialOutstandingAmount] == 0);
        auto const cleared = roundTrip(sle);
        BEAST_EXPECT(!cleared->isFieldPresent(sfConfidentialOutstandingAmount));
        BEAST_EXPECT(!cleared->isFieldPresent(sfImmutableFlags));

        // A soeDEFAULT field explicitly stored as zero cannot be read back,
        // so writers must use the proxy (or makeFieldAbsent) for zero.
        sle.setFieldU64(sfConfidentialOutstandingAmount, 0);
        BEAST_EXPECT(sle.isFieldPresent(sfConfidentialOutstandingAmount));
        bool threw = false;
        try
        {
            (void)roundTrip(sle);
        }
        catch (std::exception const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);
    }

    void
    testMPTokenFields()
    {
        testcase("MPToken fields");

        auto const issuer = account(1);
        auto const holder = account(2);
        auto const id = makeMptID(7, issuer);
        STLedgerEntry sle(keylet::mptoken(id, holder));
        sle[sfAccount] = holder;
        sle[sfMPTokenIssuanceID] = id;
        sle[sfOwnerNode] = 0;
        sle[sfPreviousTxnID] = uint256{};
        sle[sfPreviousTxnLgrSeq] = 1;

        Blob const key(33, 0x02);
        Blob const spending(66, 0x11);
        Blob const inbox(66, 0x22);
        Blob const issuerBalance(66, 0x33);
        Blob const auditorBalance(66, 0x44);
        sle.setFieldVL(sfHolderEncryptionKey, key);
        sle.setFieldVL(sfConfidentialBalanceSpending, spending);
        sle.setFieldVL(sfConfidentialBalanceInbox, inbox);
        sle.setFieldVL(sfIssuerEncryptedBalance, issuerBalance);
        sle.setFieldVL(sfAuditorEncryptedBalance, auditorBalance);

        // The version is soeOPTIONAL so an initialized holder at version 0
        // (and a counter that wrapped to 0) is stored explicitly.
        sle.setFieldU32(sfConfidentialBalanceVersion, 0);
        auto copy = roundTrip(sle);
        BEAST_EXPECT(copy->isFieldPresent(sfConfidentialBalanceVersion));
        BEAST_EXPECT(copy->getFieldU32(sfConfidentialBalanceVersion) == 0);
        BEAST_EXPECT(copy->getFieldVL(sfHolderEncryptionKey) == key);
        BEAST_EXPECT(copy->getFieldVL(sfConfidentialBalanceSpending) == spending);
        BEAST_EXPECT(copy->getFieldVL(sfConfidentialBalanceInbox) == inbox);
        BEAST_EXPECT(copy->getFieldVL(sfIssuerEncryptedBalance) == issuerBalance);
        BEAST_EXPECT(copy->getFieldVL(sfAuditorEncryptedBalance) == auditorBalance);

        sle.setFieldU32(sfConfidentialBalanceVersion, std::numeric_limits<std::uint32_t>::max());
        copy = roundTrip(sle);
        BEAST_EXPECT(
            copy->getFieldU32(sfConfidentialBalanceVersion) ==
            std::numeric_limits<std::uint32_t>::max());

        // An MPToken without confidential state is unchanged.
        sle.makeFieldAbsent(sfHolderEncryptionKey);
        sle.makeFieldAbsent(sfConfidentialBalanceSpending);
        sle.makeFieldAbsent(sfConfidentialBalanceInbox);
        sle.makeFieldAbsent(sfIssuerEncryptedBalance);
        sle.makeFieldAbsent(sfAuditorEncryptedBalance);
        sle.makeFieldAbsent(sfConfidentialBalanceVersion);
        copy = roundTrip(sle);
        BEAST_EXPECT(!copy->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(!copy->isFieldPresent(sfConfidentialBalanceVersion));
    }

    void
    testFlags()
    {
        testcase("Flags");

        std::uint32_t const otherIssuanceFlags = lsfMPTLocked | lsfMPTCanLock | lsfMPTRequireAuth |
            lsfMPTCanEscrow | lsfMPTCanTrade | lsfMPTCanTransfer | lsfMPTCanClawback;
        BEAST_EXPECT(lsfMPTCanHoldConfidentialBalance == 0x00000080);
        BEAST_EXPECT((lsfMPTCanHoldConfidentialBalance & otherIssuanceFlags) == 0);
        BEAST_EXPECT(lsifMPTCanHoldConfidentialBalance == 0x00000080);
    }

public:
    void
    run() override
    {
        testAmendment();
        testIssuanceFields();
        testMPTokenFields();
        testFlags();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTFormats, protocol, xrpl);

}  // namespace xrpl
