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

/** Focused preflight coverage for ConfidentialMPTConvertBack + Clawback (XLS-0096).

    ConvertBack apply-path success needs a 688-byte Bulletproof verifier that is
    intentionally not fabricated (see ConfidentialMPTConvertBack.cpp). These
    cases cover amendment gating and preflight structural checks only.
*/

#include <test/jtx.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/confidential_mpt.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/jss.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>
#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <string>

namespace xrpl {

class ConfidentialMPT_ConvertBackClawback_xls96_d4da_test
    : public beast::unit_test::suite
{
    static std::string
    hexZeros(std::size_t byteLen)
    {
        return std::string(byteLen * 2, '0');
    }

    static std::string
    validPointHex()
    {
        confidential_mpt::Scalar one{};
        one[31] = 1;
        auto const p = confidential_mpt::pointMulBase(one);
        if (!p)
            return hexZeros(confidential_mpt::kPointBytes);
        return strHex(Slice{p->data(), p->size()});
    }

    static std::string
    validScalarHex()
    {
        confidential_mpt::Scalar one{};
        one[31] = 1;
        return strHex(Slice{one.data(), one.size()});
    }

    static Json::Value
    makeConvertBackJson(
        test::jtx::Account const& account,
        uint192 const& issuanceID,
        std::uint64_t amount = 1,
        std::size_t zkBytes = confidential_mpt::kConvertBackSigmaBytes +
            ConfidentialMPTConvertBack::kBulletproofBytes)
    {
        Json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTConvertBack;
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = Json::UInt(amount);
        jv[sfHolderEncryptedAmount] = hexZeros(confidential_mpt::kCiphertextBytes);
        jv[sfIssuerEncryptedAmount] = hexZeros(confidential_mpt::kCiphertextBytes);
        jv[sfBlindingFactor] = validScalarHex();
        jv[sfBalanceCommitment] = validPointHex();
        jv[sfZKProof] = hexZeros(zkBytes);
        return jv;
    }

    static Json::Value
    makeClawbackJson(
        test::jtx::Account const& issuer,
        test::jtx::Account const& holder,
        uint192 const& issuanceID,
        std::uint64_t amount = 1,
        std::size_t zkBytes = confidential_mpt::kClawbackProofBytes)
    {
        Json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTClawback;
        jv[jss::Account] = issuer.human();
        jv[sfHolder] = holder.human();
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfMPTAmount] = Json::UInt(amount);
        jv[sfZKProof] = hexZeros(zkBytes);
        return jv;
    }

    void
    testFeatureDisabled()
    {
        testcase("preflight: featureConfidentialTransfer disabled");
        using namespace test::jtx;

        Env env(*this, testableAmendments() - featureConfidentialTransfer);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10'000), alice, bob);
        env.close();

        auto const id = makeMptID(env.seq(alice), alice);
        env(makeConvertBackJson(bob, id), Ter(temDISABLED));
        env(makeClawbackJson(alice, bob, id), Ter(temDISABLED));
        env.close();
    }

    void
    testConvertBackPreflight()
    {
        testcase("ConvertBack preflight field checks");
        using namespace test::jtx;

        Env env(*this, testableAmendments().set(featureConfidentialTransfer));
        Account const bob{"bob"};
        env.fund(XRP(10'000), bob);
        env.close();

        auto const id = makeMptID(1, bob);

        {
            auto jv = makeConvertBackJson(bob, id, /*amount=*/0);
            env(jv, Ter(temBAD_AMOUNT));
        }
        {
            auto jv = makeConvertBackJson(bob, id, 1, /*zkBytes=*/100);
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = makeConvertBackJson(bob, id);
            jv[sfBalanceCommitment] = hexZeros(32);
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = makeConvertBackJson(bob, id);
            jv[sfHolderEncryptedAmount] = hexZeros(32);
            env(jv, Ter(temBAD_CIPHERTEXT));
        }

        env.close();
    }

    void
    testClawbackPreflight()
    {
        testcase("Clawback preflight field checks");
        using namespace test::jtx;

        Env env(*this, testableAmendments().set(featureConfidentialTransfer));
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10'000), alice, bob);
        env.close();

        auto const id = makeMptID(env.seq(alice), alice);

        {
            auto jv = makeClawbackJson(alice, alice, id);
            env(jv, Ter(temMALFORMED));
        }
        {
            auto jv = makeClawbackJson(alice, bob, id, /*amount=*/0);
            env(jv, Ter(temBAD_AMOUNT));
        }
        {
            auto jv = makeClawbackJson(alice, bob, id, 1, /*zkBytes=*/32);
            env(jv, Ter(temMALFORMED));
        }

        env.close();
    }

public:
    void
    run() override
    {
        testFeatureDisabled();
        testConvertBackPreflight();
        testClawbackPreflight();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPT_ConvertBackClawback_xls96_d4da, app, xrpl);

}  // namespace xrpl
