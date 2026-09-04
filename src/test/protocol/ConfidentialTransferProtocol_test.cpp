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

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SOTemplate.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <string>

namespace xrpl {

class ConfidentialTransferProtocol_test : public beast::unit_test::Suite
{
    void
    testFeature()
    {
        testcase("featureConfidentialTransfer");

        auto const registered = getRegisteredFeature("ConfidentialTransfer");
        BEAST_EXPECT(registered.has_value());
        BEAST_EXPECT(*registered == featureConfidentialTransfer);
        BEAST_EXPECT(featureToName(featureConfidentialTransfer) == "ConfidentialTransfer");

        auto const& all = allAmendments();
        auto const it = all.find("ConfidentialTransfer");
        BEAST_EXPECT(it != all.end());
        BEAST_EXPECT(it->second == AmendmentSupport::Unsupported);

        // Supported::No amendments are not listed as supported.
        BEAST_EXPECT(
            detail::supportedAmendments().find("ConfidentialTransfer") ==
            detail::supportedAmendments().end());
    }

    void
    testSerializedFields()
    {
        testcase("serialized fields");

        BEAST_EXPECT(sfImmutableFlags.fieldType == STI_UINT32);
        BEAST_EXPECT(sfImmutableFlags.fieldValue == 69);
        BEAST_EXPECT(sfConfidentialBalanceVersion.fieldType == STI_UINT32);
        BEAST_EXPECT(sfConfidentialBalanceVersion.fieldValue == 70);

        BEAST_EXPECT(sfConfidentialOutstandingAmount.fieldType == STI_UINT64);
        BEAST_EXPECT(sfConfidentialOutstandingAmount.fieldValue == 32);
        BEAST_EXPECT(
            (sfConfidentialOutstandingAmount.fieldMeta & SField::kSmdBaseTen) ==
            SField::kSmdBaseTen);

        BEAST_EXPECT(sfIssuerEncryptionKey.fieldType == STI_VL);
        BEAST_EXPECT(sfIssuerEncryptionKey.fieldValue == 32);
        BEAST_EXPECT(sfAuditorEncryptionKey.fieldType == STI_VL);
        BEAST_EXPECT(sfAuditorEncryptionKey.fieldValue == 33);
        BEAST_EXPECT(sfHolderEncryptionKey.fieldType == STI_VL);
        BEAST_EXPECT(sfHolderEncryptionKey.fieldValue == 34);
        BEAST_EXPECT(sfConfidentialBalanceSpending.fieldType == STI_VL);
        BEAST_EXPECT(sfConfidentialBalanceSpending.fieldValue == 35);
        BEAST_EXPECT(sfConfidentialBalanceInbox.fieldType == STI_VL);
        BEAST_EXPECT(sfConfidentialBalanceInbox.fieldValue == 36);
        BEAST_EXPECT(sfIssuerEncryptedBalance.fieldType == STI_VL);
        BEAST_EXPECT(sfIssuerEncryptedBalance.fieldValue == 37);
        BEAST_EXPECT(sfAuditorEncryptedBalance.fieldType == STI_VL);
        BEAST_EXPECT(sfAuditorEncryptedBalance.fieldValue == 38);

        // Distinct from DynamicMPT opt-in mutability field.
        BEAST_EXPECT(sfMutableFlags.fieldValue == 53);
        BEAST_EXPECT(sfImmutableFlags.fieldValue != sfMutableFlags.fieldValue);
        BEAST_EXPECT(sfIssuerEncryptionKey.isUseful());
        BEAST_EXPECT(sfImmutableFlags.isUseful());
    }

    void
    testLedgerFormats()
    {
        testcase("ledger entry formats and flags");

        auto const* issuance = LedgerFormats::getInstance().findByType(ltMPTOKEN_ISSUANCE);
        BEAST_EXPECT(issuance != nullptr);
        auto const& issuanceTpl = issuance->getSOTemplate();
        BEAST_EXPECT(issuanceTpl.getIndex(sfIssuerEncryptionKey) != -1);
        BEAST_EXPECT(issuanceTpl.getIndex(sfAuditorEncryptionKey) != -1);
        BEAST_EXPECT(issuanceTpl.getIndex(sfConfidentialOutstandingAmount) != -1);
        BEAST_EXPECT(issuanceTpl.getIndex(sfImmutableFlags) != -1);
        BEAST_EXPECT(issuanceTpl.style(sfIssuerEncryptionKey) == SoeOptional);
        BEAST_EXPECT(issuanceTpl.style(sfAuditorEncryptionKey) == SoeOptional);
        BEAST_EXPECT(issuanceTpl.style(sfConfidentialOutstandingAmount) == SoeDefault);
        BEAST_EXPECT(issuanceTpl.style(sfImmutableFlags) == SoeOptional);

        auto const* mptoken = LedgerFormats::getInstance().findByType(ltMPTOKEN);
        BEAST_EXPECT(mptoken != nullptr);
        auto const& mptTpl = mptoken->getSOTemplate();
        BEAST_EXPECT(mptTpl.getIndex(sfHolderEncryptionKey) != -1);
        BEAST_EXPECT(mptTpl.getIndex(sfConfidentialBalanceSpending) != -1);
        BEAST_EXPECT(mptTpl.getIndex(sfConfidentialBalanceInbox) != -1);
        BEAST_EXPECT(mptTpl.getIndex(sfIssuerEncryptedBalance) != -1);
        BEAST_EXPECT(mptTpl.getIndex(sfAuditorEncryptedBalance) != -1);
        BEAST_EXPECT(mptTpl.getIndex(sfConfidentialBalanceVersion) != -1);
        BEAST_EXPECT(mptTpl.style(sfHolderEncryptionKey) == SoeOptional);
        BEAST_EXPECT(mptTpl.style(sfConfidentialBalanceSpending) == SoeOptional);
        BEAST_EXPECT(mptTpl.style(sfConfidentialBalanceInbox) == SoeOptional);
        BEAST_EXPECT(mptTpl.style(sfIssuerEncryptedBalance) == SoeOptional);
        BEAST_EXPECT(mptTpl.style(sfAuditorEncryptedBalance) == SoeOptional);
        BEAST_EXPECT(mptTpl.style(sfConfidentialBalanceVersion) == SoeOptional);

        BEAST_EXPECT(lsfMPTCanHoldConfidentialBalance == 0x00000080);
        BEAST_EXPECT(lsifMPTCanHoldConfidentialBalance == 0x00000080);

        auto const& leFlags = getAllLedgerFlags();
        bool sawIssuance = false;
        bool sawImmutable = false;
        for (auto const& [name, flags] : leFlags)
        {
            if (name == "MPTokenIssuance")
            {
                sawIssuance = true;
                BEAST_EXPECT(flags.at("lsfMPTCanHoldConfidentialBalance") == 0x00000080u);
            }
            if (name == "MPTokenIssuanceImmutable")
            {
                sawImmutable = true;
                BEAST_EXPECT(flags.at("lsifMPTCanHoldConfidentialBalance") == 0x00000080u);
            }
        }
        BEAST_EXPECT(sawIssuance);
        BEAST_EXPECT(sawImmutable);
    }

    void
    testTxFlags()
    {
        testcase("transaction flags and masks");

        BEAST_EXPECT(tfMPTCanHoldConfidentialBalance == 0x00000080);
        BEAST_EXPECT(tfMPTSetCanHoldConfidentialBalance == 0x00000100);

        BEAST_EXPECT((tfMPTokenIssuanceCreateMask & tfMPTCanHoldConfidentialBalance) == 0);
        BEAST_EXPECT((tfMPTokenIssuanceSetMask & tfMPTSetCanHoldConfidentialBalance) == 0);

        auto const& createFlags = getMPTokenIssuanceCreateFlags();
        BEAST_EXPECT(createFlags.at("tfMPTCanHoldConfidentialBalance") == 0x00000080u);

        auto const& setFlags = getMPTokenIssuanceSetFlags();
        BEAST_EXPECT(setFlags.at("tfMPTSetCanHoldConfidentialBalance") == 0x00000100u);

        bool sawCreate = false;
        bool sawSet = false;
        for (auto const& [name, flags] : getAllTxFlags())
        {
            if (name == "MPTokenIssuanceCreate")
            {
                sawCreate = true;
                BEAST_EXPECT(flags.contains("tfMPTCanHoldConfidentialBalance"));
            }
            if (name == "MPTokenIssuanceSet")
            {
                sawSet = true;
                BEAST_EXPECT(flags.contains("tfMPTSetCanHoldConfidentialBalance"));
            }
        }
        BEAST_EXPECT(sawCreate);
        BEAST_EXPECT(sawSet);
    }

    void
    testJsonKeys()
    {
        testcase("jss keys");

        BEAST_EXPECT(std::string(jss::IssuerEncryptionKey.cStr()) == "IssuerEncryptionKey");
        BEAST_EXPECT(std::string(jss::AuditorEncryptionKey.cStr()) == "AuditorEncryptionKey");
        BEAST_EXPECT(
            std::string(jss::ConfidentialOutstandingAmount.cStr()) ==
            "ConfidentialOutstandingAmount");
        BEAST_EXPECT(std::string(jss::ImmutableFlags.cStr()) == "ImmutableFlags");
        BEAST_EXPECT(std::string(jss::HolderEncryptionKey.cStr()) == "HolderEncryptionKey");
        BEAST_EXPECT(
            std::string(jss::ConfidentialBalanceSpending.cStr()) == "ConfidentialBalanceSpending");
        BEAST_EXPECT(
            std::string(jss::ConfidentialBalanceInbox.cStr()) == "ConfidentialBalanceInbox");
        BEAST_EXPECT(std::string(jss::IssuerEncryptedBalance.cStr()) == "IssuerEncryptedBalance");
        BEAST_EXPECT(std::string(jss::AuditorEncryptedBalance.cStr()) == "AuditorEncryptedBalance");
        BEAST_EXPECT(
            std::string(jss::ConfidentialBalanceVersion.cStr()) == "ConfidentialBalanceVersion");

        BEAST_EXPECT(sfIssuerEncryptionKey.getJsonName() == jss::IssuerEncryptionKey);
        BEAST_EXPECT(sfImmutableFlags.getJsonName() == jss::ImmutableFlags);
        BEAST_EXPECT(
            sfConfidentialOutstandingAmount.getJsonName() == jss::ConfidentialOutstandingAmount);
    }

public:
    void
    run() override
    {
        testFeature();
        testSerializedFields();
        testLedgerFormats();
        testTxFlags();
        testJsonKeys();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialTransferProtocol, protocol, xrpl);

}  // namespace xrpl
