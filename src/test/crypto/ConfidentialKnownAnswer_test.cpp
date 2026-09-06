/** Deterministic known-answer tests for confidential tx context IDs and EncZero.

    Public inputs are fixed synthetic account/issuer/issuance bytes. Expected
    digests and ciphertext bytes are pinned literals (not recomputed via a
    duplicate helper).
*/

#include <test/crypto/fixtures/ConfidentialKatVectors.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/ElGamal.h>
#include <xrpl/crypto/Secp256k1.h>
#include <xrpl/ledger/helpers/ConfidentialMPTHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/UintTypes.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace xrpl {
namespace {

AccountID
accountFromByte(std::uint8_t fill)
{
    AccountID id;
    std::memset(id.data(), fill, AccountID::kBytes);
    return id;
}

MPTID
issuanceFromByte(std::uint8_t fill)
{
    MPTID id;
    std::memset(id.data(), fill, MPTID::kBytes);
    return id;
}

std::array<std::uint8_t, 24>
encodeSendTxSpecific(AccountID const& destination, std::uint32_t version)
{
    std::array<std::uint8_t, 24> out{};
    std::memcpy(out.data(), destination.data(), 20);
    out[20] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    out[21] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    out[22] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    out[23] = static_cast<std::uint8_t>(version & 0xff);
    return out;
}

std::array<std::uint8_t, 24>
encodeClawbackTxSpecific(AccountID const& holder)
{
    std::array<std::uint8_t, 24> out{};
    std::memcpy(out.data(), holder.data(), 20);
    return out;
}

std::optional<Secp256k1Scalar>
scalarOne()
{
    std::array<std::uint8_t, 32> buf{};
    buf[31] = 0x01;
    return Secp256k1Scalar::parse(makeSlice(buf));
}

}  // namespace

class ConfidentialKnownAnswer_test : public beast::unit_test::Suite
{
    void
    testContextIDs()
    {
        testcase("confidentialTxContextID known answers");

        using namespace test::crypto::kat;

        auto const account = accountFromByte(0x11);
        auto const issuer = accountFromByte(0x22);
        auto const dest = accountFromByte(0x33);
        auto const holder = accountFromByte(0x44);
        auto const issuance = issuanceFromByte(0x55);
        std::uint32_t const seq = 7;
        std::uint32_t const version = 1;

        auto const convertCtx = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT), account, issuance, seq);
        BEAST_EXPECT(convertCtx == kCtx_Convert);

        auto const sendSpecific = encodeSendTxSpecific(dest, version);
        auto const sendCtx = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_SEND),
            account,
            issuance,
            seq,
            makeSlice(sendSpecific));
        BEAST_EXPECT(sendCtx == kCtx_Send);

        auto const cbSpecific = encodeSendTxSpecific(account, version);
        auto const cbCtx = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CONVERT_BACK),
            account,
            issuance,
            seq,
            makeSlice(cbSpecific));
        BEAST_EXPECT(cbCtx == kCtx_ConvertBack);

        auto const clawSpecific = encodeClawbackTxSpecific(holder);
        auto const clawCtx = confidentialTxContextID(
            static_cast<std::uint16_t>(ttCONFIDENTIAL_MPT_CLAWBACK),
            issuer,
            issuance,
            seq,
            makeSlice(clawSpecific));
        BEAST_EXPECT(clawCtx == kCtx_Clawback);
    }

    void
    testEncZero()
    {
        testcase("EncZero scalar and ciphertext known answers");

        using namespace test::crypto::kat;

        auto const account = accountFromByte(0x11);
        auto const issuer = accountFromByte(0x22);
        auto const issuance = issuanceFromByte(0x55);

        std::vector<std::uint8_t> msg;
        std::string_view const tag = "EncZero";
        msg.insert(msg.end(), tag.begin(), tag.end());
        msg.insert(msg.end(), account.data(), account.data() + AccountID::kBytes);
        msg.insert(msg.end(), issuer.data(), issuer.data() + AccountID::kBytes);
        msg.insert(msg.end(), issuance.data(), issuance.data() + MPTID::kBytes);

        auto const r = hashToCurveScalar(makeSlice(msg));
        BEAST_EXPECT(r);
        if (!r)
            return;
        BEAST_EXPECT(r->serialize() == kEncZero_r);

        auto const s1 = scalarOne();
        BEAST_EXPECT(s1);
        auto const G = generatorMultiply(*s1);
        BEAST_EXPECT(G);
        auto const ct = encZero(account, issuer, issuance, *G);
        BEAST_EXPECT(ct && ct->size() == ElGamalCiphertext::kSerializedSize);
        if (!ct)
            return;
        BEAST_EXPECT(std::equal(ct->begin(), ct->end(), kEncZero_ct.begin(), kEncZero_ct.end()));
    }

    void
    run() override
    {
        testContextIDs();
        testEncZero();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialKnownAnswer, crypto, xrpl);

}  // namespace xrpl
