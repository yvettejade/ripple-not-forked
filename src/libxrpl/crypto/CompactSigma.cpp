#include <xrpl/crypto/CompactSigma.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/crypto/secure_erase.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <cstring>
#include <string_view>
#include <vector>

namespace xrpl {
namespace {

constexpr std::string_view kTagRegister = "CMPT_POK_SK_REGISTER";
constexpr std::string_view kTagSend = "CMPT_SEND_SIGMA";
constexpr std::string_view kTagConvertBack = "CMPT_CONVERTBACK_SIGMA";
constexpr std::string_view kTagClawback = "CMPT_CLAWBACK_SIGMA";
constexpr std::string_view kTagPedersenH = "CMPT_PEDERSEN_H";

constexpr std::uint8_t kCompressedG[33] = {
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0,
    0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
    0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
};

bool
validContextID(Slice id)
{
    return id.size() == kTransactionContextIDSize;
}

std::optional<Secp256k1Scalar>
sampleScalar()
{
    for (int i = 0; i < 128; ++i)
    {
        std::array<std::uint8_t, Secp256k1Scalar::kSerializedSize> buf{};
        cryptoPrng()(buf.data(), buf.size());
        auto s = Secp256k1Scalar::parse(makeSlice(buf));
        secureErase(buf.data(), buf.size());
        if (s)
            return s;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

bool
scalarsEqualCT(Secp256k1Scalar const& a, Secp256k1Scalar const& b)
{
    return CRYPTO_memcmp(a.data(), b.data(), Secp256k1Scalar::kSerializedSize) == 0;
}

void
writeScalar(std::uint8_t*& out, Secp256k1Scalar const& s)
{
    s.serialize(out);
    out += Secp256k1Scalar::kSerializedSize;
}

std::optional<Secp256k1Scalar>
readScalar(std::uint8_t const*& p, std::uint8_t const* end)
{
    if (static_cast<std::size_t>(end - p) < Secp256k1Scalar::kSerializedSize)
        return std::nullopt;
    auto s = Secp256k1Scalar::parse(Slice(p, Secp256k1Scalar::kSerializedSize));
    p += Secp256k1Scalar::kSerializedSize;
    return s;
}

std::optional<Secp256k1Scalar>
response(Secp256k1Scalar const& alpha, Secp256k1Scalar const& e, Secp256k1Field const& witness)
{
    auto const prod = fieldMul(Secp256k1Field::fromScalar(e), witness);
    auto const sum = fieldAdd(Secp256k1Field::fromScalar(alpha), prod);
    return sum.toScalar();
}

std::optional<Secp256k1Scalar>
response(Secp256k1Scalar const& alpha, Secp256k1Scalar const& e, Secp256k1Scalar const& witness)
{
    return response(alpha, e, Secp256k1Field::fromScalar(witness));
}

std::optional<Secp256k1Point>
pointSub(Secp256k1Point const& a, Secp256k1Point const& b)
{
    return pointSubtract(a, b);
}

std::optional<Secp256k1Point>
pointAddSub(Secp256k1Point const& a, Secp256k1Point const& b, Secp256k1Point const& c)
{
    auto const ab = pointAdd(a, b);
    if (!ab)
        return std::nullopt;
    return pointSubtract(*ab, c);
}

bool
sameC1(std::span<ElGamalCiphertext const> cts)
{
    if (cts.empty())
        return false;
    for (std::size_t i = 1; i < cts.size(); ++i)
    {
        if (!(cts[i].c1() == cts[0].c1()))
            return false;
    }
    return true;
}

std::array<std::uint8_t, 32>
sha512Half(std::uint8_t const* data, std::size_t len)
{
    std::uint8_t dig[SHA512_DIGEST_LENGTH];
    SHA512(data, len, dig);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), dig, 32);
    return out;
}

}  // namespace

//------------------------------------------------------------------------------

Secp256k1Point const&
pedersenH()
{
    // Spec gap: NUMS derivation for H is unspecified. Try-and-increment below.
    static Secp256k1Point const kH = [] {
        auto const g = *Secp256k1Point::parse(Slice(kCompressedG, sizeof(kCompressedG)));
        for (std::uint32_t counter = 0;; ++counter)
        {
            std::vector<std::uint8_t> msg;
            msg.reserve(kTagPedersenH.size() + 33 + 4);
            msg.insert(msg.end(), kTagPedersenH.begin(), kTagPedersenH.end());
            msg.insert(msg.end(), kCompressedG, kCompressedG + 33);
            msg.push_back(static_cast<std::uint8_t>((counter >> 24) & 0xff));
            msg.push_back(static_cast<std::uint8_t>((counter >> 16) & 0xff));
            msg.push_back(static_cast<std::uint8_t>((counter >> 8) & 0xff));
            msg.push_back(static_cast<std::uint8_t>(counter & 0xff));

            auto const half = sha512Half(msg.data(), msg.size());
            std::array<std::uint8_t, 33> enc{};
            enc[0] = 0x02;
            std::memcpy(enc.data() + 1, half.data(), 32);

            auto pt = Secp256k1Point::parse(makeSlice(enc));
            if (pt && !(*pt == g))
                return *pt;
        }
    }();
    return kH;
}

std::optional<Secp256k1Point>
pedersenCommit(std::uint64_t value, Secp256k1Scalar const& blinding)
{
    return pedersenCommit(Secp256k1Field::fromUint64(value), blinding);
}

std::optional<Secp256k1Point>
pedersenCommit(Secp256k1Field const& value, Secp256k1Scalar const& blinding)
{
    auto const blindH = pointMultiply(pedersenH(), blinding);
    if (!blindH)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }
    if (value.isZero())
        return blindH;

    auto const vG = generatorMultiply(value);
    if (!vG)
    {
        // LCOV_EXCL_START
        return std::nullopt;
        // LCOV_EXCL_STOP
    }
    return pointAdd(*vG, *blindH);
}

//------------------------------------------------------------------------------

void
CompactTranscript::appendDomainTag(std::string_view tag)
{
    buf_.insert(buf_.end(), tag.begin(), tag.end());
}

void
CompactTranscript::append(Secp256k1Point const& point)
{
    auto const enc = point.serialize();
    buf_.insert(buf_.end(), enc.begin(), enc.end());
}

void
CompactTranscript::append(Secp256k1Scalar const& scalar)
{
    auto const enc = scalar.serialize();
    buf_.insert(buf_.end(), enc.begin(), enc.end());
}

void
CompactTranscript::append(Slice bytes)
{
    buf_.insert(buf_.end(), bytes.data(), bytes.data() + bytes.size());
}

std::optional<Secp256k1Scalar>
hashToCurveScalar(Slice message)
{
    // Spec gap: H() and Z_n reduction are unspecified. SHA-512 + counter below.
    for (unsigned counter = 0; counter < 256; ++counter)
    {
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, message.data(), message.size());
        if (counter > 0)
        {
            auto const c = static_cast<std::uint8_t>(counter - 1);
            SHA512_Update(&ctx, &c, 1);
        }
        std::uint8_t dig[SHA512_DIGEST_LENGTH];
        SHA512_Final(dig, &ctx);
        if (auto s = Secp256k1Scalar::parse(Slice(dig, 32)))
            return s;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

std::optional<Secp256k1Scalar>
CompactTranscript::challenge()
{
    return hashToCurveScalar(makeSlice(buf_));
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kRegisterPoKSize>>
proveRegisterPoK(Secp256k1Scalar const& sk, Secp256k1Point const& pk, Slice txContextID)
{
    if (!validContextID(txContextID))
        return std::nullopt;

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        auto k = sampleScalar();
        if (!k)
            return std::nullopt;

        auto T = generatorMultiply(*k);
        if (!T)
            continue;

        CompactTranscript tr;
        tr.appendDomainTag(kTagRegister);
        tr.append(pk);
        tr.append(*T);
        tr.append(txContextID);
        auto e = tr.challenge();
        if (!e)
            continue;

        auto s = response(*k, *e, sk);
        if (!s)
            continue;

        std::array<std::uint8_t, kRegisterPoKSize> out{};
        auto* p = out.data();
        writeScalar(p, *e);
        writeScalar(p, *s);
        return out;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

bool
verifyRegisterPoK(Secp256k1Point const& pk, Slice proof, Slice txContextID)
{
    if (!validContextID(txContextID) || proof.size() != kRegisterPoKSize)
        return false;

    auto const* p = proof.data();
    auto const* end = p + proof.size();
    auto e = readScalar(p, end);
    auto s = readScalar(p, end);
    if (!e || !s)
        return false;

    auto const sG = generatorMultiply(*s);
    auto const ePk = pointMultiply(pk, *e);
    if (!sG || !ePk)
        return false;
    auto T = pointSub(*sG, *ePk);
    if (!T)
        return false;

    CompactTranscript tr;
    tr.appendDomainTag(kTagRegister);
    tr.append(pk);
    tr.append(*T);
    tr.append(txContextID);
    auto e2 = tr.challenge();
    if (!e2)
        return false;

    return scalarsEqualCT(*e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kSendSigmaSize>>
proveSendSigma(
    std::uint64_t amount,
    Secp256k1Scalar const& randomness,
    std::uint64_t balance,
    Secp256k1Scalar const& balanceBlinding,
    Secp256k1Scalar const& skA,
    std::span<Secp256k1Point const> recipientPks,
    Secp256k1Point const& senderPk,
    std::span<ElGamalCiphertext const> ciphertexts,
    Secp256k1Point const& pcM,
    Secp256k1Point const& pcB,
    ElGamalCiphertext const& balanceCiphertext,
    Slice txContextID)
{
    // Spec inconsistency: xls-0096 uses per-recipient 66-byte (C1||C2); the
    // addendum uses shared C1 + C2,i. Require identical C1 across inputs.
    if (!validContextID(txContextID) || recipientPks.empty() ||
        recipientPks.size() != ciphertexts.size() || !sameC1(ciphertexts))
        return std::nullopt;

    auto const mField = Secp256k1Field::fromUint64(amount);
    auto const bField = Secp256k1Field::fromUint64(balance);
    auto const& C1 = ciphertexts[0].c1();
    auto const& B1 = balanceCiphertext.c1();
    auto const& B2 = balanceCiphertext.c2();
    auto const n = recipientPks.size();

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        auto am = sampleScalar();
        auto ar = sampleScalar();
        auto ab = sampleScalar();
        auto arho = sampleScalar();
        auto ask = sampleScalar();
        if (!am || !ar || !ab || !arho || !ask)
            return std::nullopt;

        auto T1 = generatorMultiply(*ar);
        if (!T1)
            continue;

        auto const amG = generatorMultiply(*am);
        if (!amG)
            continue;

        std::vector<Secp256k1Point> T2;
        T2.reserve(n);
        bool ok = true;
        for (std::size_t i = 0; i < n; ++i)
        {
            auto const arPi = pointMultiply(recipientPks[i], *ar);
            if (!arPi)
            {
                ok = false;
                break;
            }
            auto t2 = pointAdd(*amG, *arPi);
            if (!t2)
            {
                ok = false;
                break;
            }
            T2.push_back(*t2);
        }
        if (!ok)
            continue;

        auto const arH = pointMultiply(pedersenH(), *ar);
        if (!arH)
            continue;
        auto Tm = pointAdd(*amG, *arH);
        if (!Tm)
            continue;

        auto const abG = generatorMultiply(*ab);
        auto const arhoH = pointMultiply(pedersenH(), *arho);
        if (!abG || !arhoH)
            continue;
        auto Tb = pointAdd(*abG, *arhoH);
        if (!Tb)
            continue;

        auto Tsk1 = generatorMultiply(*ask);
        if (!Tsk1)
            continue;

        auto const askB1 = pointMultiply(B1, *ask);
        if (!askB1)
            continue;
        auto Tsk2 = pointAdd(*abG, *askB1);
        if (!Tsk2)
            continue;

        CompactTranscript tr;
        tr.appendDomainTag(kTagSend);
        for (auto const& Pi : recipientPks)
            tr.append(Pi);
        tr.append(senderPk);
        tr.append(C1);
        for (auto const& ct : ciphertexts)
            tr.append(ct.c2());
        tr.append(pcM);
        tr.append(pcB);
        tr.append(B1);
        tr.append(B2);
        tr.append(*T1);
        for (auto const& t2 : T2)
            tr.append(t2);
        tr.append(*Tm);
        tr.append(*Tb);
        tr.append(*Tsk1);
        tr.append(*Tsk2);
        tr.append(txContextID);

        auto e = tr.challenge();
        if (!e)
            continue;

        auto zm = response(*am, *e, mField);
        auto zr = response(*ar, *e, randomness);
        auto zb = response(*ab, *e, bField);
        auto zrho = response(*arho, *e, balanceBlinding);
        auto zsk = response(*ask, *e, skA);
        if (!zm || !zr || !zb || !zrho || !zsk)
            continue;

        std::array<std::uint8_t, kSendSigmaSize> out{};
        auto* p = out.data();
        writeScalar(p, *e);
        writeScalar(p, *zm);
        writeScalar(p, *zr);
        writeScalar(p, *zb);
        writeScalar(p, *zrho);
        writeScalar(p, *zsk);
        return out;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

bool
verifySendSigma(
    std::span<Secp256k1Point const> recipientPks,
    Secp256k1Point const& senderPk,
    std::span<ElGamalCiphertext const> ciphertexts,
    Secp256k1Point const& pcM,
    Secp256k1Point const& pcB,
    ElGamalCiphertext const& balanceCiphertext,
    Slice proof,
    Slice txContextID)
{
    // Spec inconsistency: require identical C1 across per-recipient 66-byte cts.
    if (!validContextID(txContextID) || proof.size() != kSendSigmaSize || recipientPks.empty() ||
        recipientPks.size() != ciphertexts.size() || !sameC1(ciphertexts))
        return false;

    auto const* p = proof.data();
    auto const* end = p + proof.size();
    auto e = readScalar(p, end);
    auto zm = readScalar(p, end);
    auto zr = readScalar(p, end);
    auto zb = readScalar(p, end);
    auto zrho = readScalar(p, end);
    auto zsk = readScalar(p, end);
    if (!e || !zm || !zr || !zb || !zrho || !zsk)
        return false;

    auto const& C1 = ciphertexts[0].c1();
    auto const& B1 = balanceCiphertext.c1();
    auto const& B2 = balanceCiphertext.c2();
    auto const n = recipientPks.size();

    auto const zrG = generatorMultiply(*zr);
    auto const eC1 = pointMultiply(C1, *e);
    if (!zrG || !eC1)
        return false;
    auto T1 = pointSub(*zrG, *eC1);
    if (!T1)
        return false;

    auto const zmG = generatorMultiply(*zm);
    if (!zmG)
        return false;
    std::vector<Secp256k1Point> T2;
    T2.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        auto const zrPi = pointMultiply(recipientPks[i], *zr);
        auto const eC2 = pointMultiply(ciphertexts[i].c2(), *e);
        if (!zrPi || !eC2)
            return false;
        auto t2 = pointAddSub(*zmG, *zrPi, *eC2);
        if (!t2)
            return false;
        T2.push_back(*t2);
    }

    auto const zrH = pointMultiply(pedersenH(), *zr);
    auto const ePCm = pointMultiply(pcM, *e);
    if (!zrH || !ePCm)
        return false;
    auto Tm = pointAddSub(*zmG, *zrH, *ePCm);
    if (!Tm)
        return false;

    auto const zbG = generatorMultiply(*zb);
    auto const zrhoH = pointMultiply(pedersenH(), *zrho);
    auto const ePCb = pointMultiply(pcB, *e);
    if (!zbG || !zrhoH || !ePCb)
        return false;
    auto Tb = pointAddSub(*zbG, *zrhoH, *ePCb);
    if (!Tb)
        return false;

    auto const zskG = generatorMultiply(*zsk);
    auto const ePA = pointMultiply(senderPk, *e);
    if (!zskG || !ePA)
        return false;
    auto Tsk1 = pointSub(*zskG, *ePA);
    if (!Tsk1)
        return false;

    auto const zskB1 = pointMultiply(B1, *zsk);
    auto const eB2 = pointMultiply(B2, *e);
    if (!zskB1 || !eB2)
        return false;
    auto Tsk2 = pointAddSub(*zbG, *zskB1, *eB2);
    if (!Tsk2)
        return false;

    CompactTranscript tr;
    tr.appendDomainTag(kTagSend);
    for (auto const& Pi : recipientPks)
        tr.append(Pi);
    tr.append(senderPk);
    tr.append(C1);
    for (auto const& ct : ciphertexts)
        tr.append(ct.c2());
    tr.append(pcM);
    tr.append(pcB);
    tr.append(B1);
    tr.append(B2);
    tr.append(*T1);
    for (auto const& t2 : T2)
        tr.append(t2);
    tr.append(*Tm);
    tr.append(*Tb);
    tr.append(*Tsk1);
    tr.append(*Tsk2);
    tr.append(txContextID);

    auto e2 = tr.challenge();
    if (!e2)
        return false;

    return scalarsEqualCT(*e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kConvertBackSigmaSize>>
proveConvertBackSigma(
    std::uint64_t balance,
    Secp256k1Scalar const& balanceBlinding,
    Secp256k1Scalar const& skA,
    Secp256k1Point const& senderPk,
    ElGamalCiphertext const& balanceCiphertext,
    Secp256k1Point const& pcB,
    Slice txContextID)
{
    if (!validContextID(txContextID))
        return std::nullopt;

    auto const bField = Secp256k1Field::fromUint64(balance);
    auto const& B1 = balanceCiphertext.c1();

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        auto ab = sampleScalar();
        auto arho = sampleScalar();
        auto ask = sampleScalar();
        if (!ab || !arho || !ask)
            return std::nullopt;

        auto Tsk1 = generatorMultiply(*ask);
        if (!Tsk1)
            continue;

        auto const abG = generatorMultiply(*ab);
        auto const askB1 = pointMultiply(B1, *ask);
        if (!abG || !askB1)
            continue;
        auto Tsk2 = pointAdd(*abG, *askB1);
        if (!Tsk2)
            continue;

        auto const arhoH = pointMultiply(pedersenH(), *arho);
        if (!arhoH)
            continue;
        auto Tb = pointAdd(*abG, *arhoH);
        if (!Tb)
            continue;

        CompactTranscript tr;
        tr.appendDomainTag(kTagConvertBack);
        tr.append(senderPk);
        tr.append(B1);
        tr.append(balanceCiphertext.c2());
        tr.append(pcB);
        tr.append(*Tsk1);
        tr.append(*Tsk2);
        tr.append(*Tb);
        tr.append(txContextID);

        auto e = tr.challenge();
        if (!e)
            continue;

        auto zb = response(*ab, *e, bField);
        auto zrho = response(*arho, *e, balanceBlinding);
        auto zsk = response(*ask, *e, skA);
        if (!zb || !zrho || !zsk)
            continue;

        std::array<std::uint8_t, kConvertBackSigmaSize> out{};
        auto* p = out.data();
        writeScalar(p, *e);
        writeScalar(p, *zb);
        writeScalar(p, *zrho);
        writeScalar(p, *zsk);
        return out;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

bool
verifyConvertBackSigma(
    Secp256k1Point const& senderPk,
    ElGamalCiphertext const& balanceCiphertext,
    Secp256k1Point const& pcB,
    Slice proof,
    Slice txContextID)
{
    if (!validContextID(txContextID) || proof.size() != kConvertBackSigmaSize)
        return false;

    auto const* p = proof.data();
    auto const* end = p + proof.size();
    auto e = readScalar(p, end);
    auto zb = readScalar(p, end);
    auto zrho = readScalar(p, end);
    auto zsk = readScalar(p, end);
    if (!e || !zb || !zrho || !zsk)
        return false;

    auto const& B1 = balanceCiphertext.c1();
    auto const& B2 = balanceCiphertext.c2();

    auto const zskG = generatorMultiply(*zsk);
    auto const ePA = pointMultiply(senderPk, *e);
    if (!zskG || !ePA)
        return false;
    auto Tsk1 = pointSub(*zskG, *ePA);
    if (!Tsk1)
        return false;

    auto const zbG = generatorMultiply(*zb);
    auto const zskB1 = pointMultiply(B1, *zsk);
    auto const eB2 = pointMultiply(B2, *e);
    if (!zbG || !zskB1 || !eB2)
        return false;
    auto Tsk2 = pointAddSub(*zbG, *zskB1, *eB2);
    if (!Tsk2)
        return false;

    auto const zrhoH = pointMultiply(pedersenH(), *zrho);
    auto const ePCb = pointMultiply(pcB, *e);
    if (!zrhoH || !ePCb)
        return false;
    auto Tb = pointAddSub(*zbG, *zrhoH, *ePCb);
    if (!Tb)
        return false;

    CompactTranscript tr;
    tr.appendDomainTag(kTagConvertBack);
    tr.append(senderPk);
    tr.append(B1);
    tr.append(B2);
    tr.append(pcB);
    tr.append(*Tsk1);
    tr.append(*Tsk2);
    tr.append(*Tb);
    tr.append(txContextID);

    auto e2 = tr.challenge();
    if (!e2)
        return false;

    return scalarsEqualCT(*e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kClawbackSigmaSize>>
proveClawbackSigma(
    std::uint64_t amount,
    Secp256k1Scalar const& issuerSk,
    Secp256k1Point const& issuerPk,
    ElGamalCiphertext const& issuerCiphertext,
    Slice txContextID)
{
    if (!validContextID(txContextID))
        return std::nullopt;

    // Spec gap: m·G must be hashed as a compressed point; m = 0 → ∞ has no
    // compressed encoding, so clawback of zero is rejected here.
    if (amount == 0)
        return std::nullopt;

    auto const mG = generatorMultiply(Secp256k1Field::fromUint64(amount));
    if (!mG)
        return std::nullopt;

    auto const& C1 = issuerCiphertext.c1();

    for (int attempt = 0; attempt < 16; ++attempt)
    {
        auto ask = sampleScalar();
        if (!ask)
            return std::nullopt;

        auto T1 = generatorMultiply(*ask);
        auto T2 = pointMultiply(C1, *ask);
        if (!T1 || !T2)
            continue;

        CompactTranscript tr;
        tr.appendDomainTag(kTagClawback);
        tr.append(issuerPk);
        tr.append(C1);
        tr.append(issuerCiphertext.c2());
        tr.append(*mG);
        tr.append(*T1);
        tr.append(*T2);
        tr.append(txContextID);

        auto e = tr.challenge();
        if (!e)
            continue;

        auto zsk = response(*ask, *e, issuerSk);
        if (!zsk)
            continue;

        std::array<std::uint8_t, kClawbackSigmaSize> out{};
        auto* p = out.data();
        writeScalar(p, *e);
        writeScalar(p, *zsk);
        return out;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

bool
verifyClawbackSigma(
    std::uint64_t amount,
    Secp256k1Point const& issuerPk,
    ElGamalCiphertext const& issuerCiphertext,
    Slice proof,
    Slice txContextID)
{
    if (!validContextID(txContextID) || proof.size() != kClawbackSigmaSize)
        return false;

    // Spec gap: m = 0 → m·G = ∞ cannot be serialized as a compressed point.
    if (amount == 0)
        return false;

    auto const mG = generatorMultiply(Secp256k1Field::fromUint64(amount));
    if (!mG)
        return false;

    auto const* p = proof.data();
    auto const* end = p + proof.size();
    auto e = readScalar(p, end);
    auto zsk = readScalar(p, end);
    if (!e || !zsk)
        return false;

    auto const& C1 = issuerCiphertext.c1();
    auto const& C2 = issuerCiphertext.c2();

    auto const zskG = generatorMultiply(*zsk);
    auto const eP = pointMultiply(issuerPk, *e);
    if (!zskG || !eP)
        return false;
    auto T1 = pointSub(*zskG, *eP);
    if (!T1)
        return false;

    auto const C2minus = pointSubtract(C2, *mG);
    if (!C2minus)
        return false;
    auto const zskC1 = pointMultiply(C1, *zsk);
    auto const eDiff = pointMultiply(*C2minus, *e);
    if (!zskC1 || !eDiff)
        return false;
    auto T2 = pointSub(*zskC1, *eDiff);
    if (!T2)
        return false;

    CompactTranscript tr;
    tr.appendDomainTag(kTagClawback);
    tr.append(issuerPk);
    tr.append(C1);
    tr.append(C2);
    tr.append(*mG);
    tr.append(*T1);
    tr.append(*T2);
    tr.append(txContextID);

    auto e2 = tr.challenge();
    if (!e2)
        return false;

    return scalarsEqualCT(*e, *e2);
}

}  // namespace xrpl
