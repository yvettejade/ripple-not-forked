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

/** Focused preflight coverage for ConfidentialMPTSend (XLS-0096).

    Preflight coverage for amendment gating and field checks. Aggregated
    Bulletproof prove/verify is covered in xrpl.crypto.ConfidentialMPT.
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
#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <string>

namespace xrpl {

class ConfidentialMPTSend_xls0096_875f_test : public beast::unit_test::Suite
{
    static std::string
    hexZeros(std::size_t byteLen)
    {
        return std::string(byteLen * 2, '0');
    }

    /** A valid compressed secp256k1 point (1·G) for size-gated tests. */
    static std::string
    validPointHex()
    {
        confidential_mpt::Scalar one{};
        one[31] = 1;
        auto const p = confidential_mpt::pointMulBase(one);
        if (!p)
            return hexZeros(33);
        return strHex(Slice{p->data(), p->size()});
    }

    /** Minimal Send JSON with syntactically sized crypto fields. */
    static json::Value
    makeSendJson(
        test::jtx::Account const& sender,
        test::jtx::Account const& dest,
        uint192 const& issuanceID,
        std::size_t zkBytes = ConfidentialMPTSend::kZKProofBytes)
    {
        json::Value jv;
        jv[jss::TransactionType] = jss::ConfidentialMPTSend;
        jv[jss::Account] = sender.human();
        jv[jss::Destination] = dest.human();
        jv[sfMPTokenIssuanceID] = to_string(issuanceID);
        jv[sfSenderEncryptedAmount] = hexZeros(66);
        jv[sfDestinationEncryptedAmount] = hexZeros(66);
        jv[sfIssuerEncryptedAmount] = hexZeros(66);
        jv[sfBalanceCommitment] = hexZeros(33);
        jv[sfAmountCommitment] = hexZeros(33);
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
        env(makeSendJson(alice, bob, id), Ter(temDISABLED));
        env.close();
    }

    void
    testPreflightMalformed()
    {
        testcase("preflight: self-send and field sizes");
        using namespace test::jtx;

        Env env(*this, testableAmendments().set(featureConfidentialTransfer));
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10'000), issuer, alice, bob);
        env.close();

        auto const id = makeMptID(env.seq(issuer), issuer);

        // Sender role is derivable from the ID and rejected in preflight.
        {
            auto jv = makeSendJson(issuer, bob, id);
            auto const pt = validPointHex();
            auto const ct = pt + pt;
            jv[sfBalanceCommitment] = pt;
            jv[sfAmountCommitment] = pt;
            jv[sfSenderEncryptedAmount] = ct;
            jv[sfDestinationEncryptedAmount] = ct;
            jv[sfIssuerEncryptedAmount] = ct;
            env(jv, Ter(temMALFORMED));
        }

        // Sender == Destination
        {
            auto jv = makeSendJson(alice, alice, id);
            env(jv, Ter(temMALFORMED));
        }

        // ZKProof wrong length
        {
            auto jv = makeSendJson(alice, bob, id, /*zkBytes=*/100);
            env(jv, Ter(temMALFORMED));
        }
        // XLS-0096 Send ZKProof is exactly 946 bytes (192 + 754).
        {
            constexpr auto kExact = ConfidentialMPTSend::kZKProofBytes;
            static_assert(kExact == 946u);
            env(makeSendJson(alice, bob, id, kExact - 1), Ter(temMALFORMED));
            env(makeSendJson(alice, bob, id, kExact + 1), Ter(temMALFORMED));
        }

        // Commitment wrong length
        {
            auto jv = makeSendJson(alice, bob, id);
            jv[sfBalanceCommitment] = hexZeros(32);
            env(jv, Ter(temMALFORMED));
        }

        // Invalid commitment point encoding (33 zero bytes)
        {
            auto jv = makeSendJson(alice, bob, id);
            env(jv, Ter(temMALFORMED));
        }

        // Ciphertext wrong length (valid commitments so we reach ciphertext checks)
        {
            auto jv = makeSendJson(alice, bob, id);
            auto const pt = validPointHex();
            jv[sfBalanceCommitment] = pt;
            jv[sfAmountCommitment] = pt;
            jv[sfSenderEncryptedAmount] = hexZeros(32);
            jv[sfDestinationEncryptedAmount] = hexZeros(32);
            jv[sfIssuerEncryptedAmount] = hexZeros(32);
            env(jv, Ter(temBAD_CIPHERTEXT));
        }

        env.close();
    }

public:
    void
    run() override
    {
        testFeatureDisabled();
        testPreflightMalformed();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSend_xls0096_875f, app, xrpl);

}  // namespace xrpl
