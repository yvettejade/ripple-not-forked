#include <xrpl/crypto/Bulletproofs.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/CompactSigma.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/crypto/secure_erase.h>

#include <openssl/sha.h>

#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

namespace xrpl {
namespace {

constexpr std::size_t kN = 64;
constexpr std::size_t kLogN = 6;
constexpr std::size_t kLogAgg = 7;  // log2(128)
constexpr std::string_view kTagSingle = "CMPT_BP_RANGE64";
constexpr std::string_view kTagAgg = "CMPT_BP_RANGE64_AGG2";
constexpr std::string_view kTagG = "CMPT_BP_G";
constexpr std::string_view kTagH = "CMPT_BP_H";
constexpr std::string_view kTagU = "CMPT_BP_U";

constexpr std::uint8_t kCompressedG[33] = {
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0,
    0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
    0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
};

[[nodiscard]] Secp256k1Field
one()
{
    return Secp256k1Field::fromUint64(1);
}

[[nodiscard]] std::optional<Secp256k1Scalar>
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

[[nodiscard]] std::array<std::uint8_t, 32>
sha512Half(std::uint8_t const* data, std::size_t len)
{
    std::uint8_t dig[SHA512_DIGEST_LENGTH];
    SHA512(data, len, dig);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), dig, 32);
    return out;
}

[[nodiscard]] std::optional<Secp256k1Point>
numsPoint(std::string_view tag, std::uint32_t index)
{
    auto const g = *Secp256k1Point::parse(Slice(kCompressedG, sizeof(kCompressedG)));
    auto const& hPed = pedersenH();
    for (std::uint32_t extra = 0; extra < 256; ++extra)
    {
        std::vector<std::uint8_t> msg;
        msg.reserve(tag.size() + 8);
        msg.insert(msg.end(), tag.begin(), tag.end());
        auto const ctr = index + extra * 65536u;
        msg.push_back(static_cast<std::uint8_t>((ctr >> 24) & 0xff));
        msg.push_back(static_cast<std::uint8_t>((ctr >> 16) & 0xff));
        msg.push_back(static_cast<std::uint8_t>((ctr >> 8) & 0xff));
        msg.push_back(static_cast<std::uint8_t>(ctr & 0xff));
        auto const half = sha512Half(msg.data(), msg.size());
        std::array<std::uint8_t, 33> enc{};
        enc[0] = 0x02;
        std::memcpy(enc.data() + 1, half.data(), 32);
        auto pt = Secp256k1Point::parse(makeSlice(enc));
        if (pt && !(*pt == g) && !(*pt == hPed))
            return pt;
    }
    // LCOV_EXCL_START
    return std::nullopt;
    // LCOV_EXCL_STOP
}

struct BpGenerators
{
    std::vector<Secp256k1Point> g;
    std::vector<Secp256k1Point> h;
    Secp256k1Point u;
};

[[nodiscard]] BpGenerators const&
generators()
{
    static BpGenerators const kGens = [] {
        BpGenerators out{
            {},
            {},
            *numsPoint(kTagU, 0),
        };
        out.g.reserve(kN * 2);
        out.h.reserve(kN * 2);
        for (std::uint32_t i = 0; i < kN * 2; ++i)
        {
            out.g.push_back(*numsPoint(kTagG, i));
            out.h.push_back(*numsPoint(kTagH, i));
        }
        return out;
    }();
    return kGens;
}

[[nodiscard]] std::optional<Secp256k1Point>
msm(std::vector<Secp256k1Point> const& pts, std::vector<Secp256k1Field> const& scs)
{
    if (pts.size() != scs.size())
        return std::nullopt;
    std::optional<Secp256k1Point> acc;
    for (std::size_t i = 0; i < pts.size(); ++i)
    {
        if (scs[i].isZero())
            continue;
        auto term = pointMultiply(pts[i], scs[i]);
        if (!term)
            return std::nullopt;
        if (!acc)
            acc = *term;
        else
            acc = pointAdd(*acc, *term);
        if (!acc)
            return std::nullopt;
    }
    return acc;
}

[[nodiscard]] std::optional<Secp256k1Point>
addPoints(std::optional<Secp256k1Point> const& a, std::optional<Secp256k1Point> const& b)
{
    if (!a)
        return b;
    if (!b)
        return a;
    return pointAdd(*a, *b);
}

[[nodiscard]] std::vector<Secp256k1Field>
powers(Secp256k1Field const& y, std::size_t n)
{
    std::vector<Secp256k1Field> out;
    out.reserve(n);
    auto cur = one();
    for (std::size_t i = 0; i < n; ++i)
    {
        out.push_back(cur);
        cur = fieldMul(cur, y);
    }
    return out;
}

[[nodiscard]] std::vector<Secp256k1Field>
twoPowers(std::size_t n)
{
    std::vector<Secp256k1Field> out;
    out.reserve(n);
    auto cur = one();
    for (std::size_t i = 0; i < n; ++i)
    {
        out.push_back(cur);
        cur = fieldAdd(cur, cur);
    }
    return out;
}

[[nodiscard]] Secp256k1Field
inner(std::vector<Secp256k1Field> const& a, std::vector<Secp256k1Field> const& b)
{
    auto acc = Secp256k1Field::zero();
    for (std::size_t i = 0; i < a.size(); ++i)
        acc = fieldAdd(acc, fieldMul(a[i], b[i]));
    return acc;
}

[[nodiscard]] std::vector<Secp256k1Field>
hadamard(std::vector<Secp256k1Field> const& a, std::vector<Secp256k1Field> const& b)
{
    std::vector<Secp256k1Field> out;
    out.reserve(a.size());
    for (std::size_t i = 0; i < a.size(); ++i)
        out.push_back(fieldMul(a[i], b[i]));
    return out;
}

[[nodiscard]] std::vector<Secp256k1Field>
vecAdd(std::vector<Secp256k1Field> const& a, std::vector<Secp256k1Field> const& b)
{
    std::vector<Secp256k1Field> out;
    out.reserve(a.size());
    for (std::size_t i = 0; i < a.size(); ++i)
        out.push_back(fieldAdd(a[i], b[i]));
    return out;
}

[[nodiscard]] std::vector<Secp256k1Field>
vecScale(std::vector<Secp256k1Field> const& a, Secp256k1Field const& s)
{
    std::vector<Secp256k1Field> out;
    out.reserve(a.size());
    for (auto const& x : a)
        out.push_back(fieldMul(x, s));
    return out;
}

[[nodiscard]] std::vector<Secp256k1Field>
ones(std::size_t n)
{
    return std::vector<Secp256k1Field>(n, one());
}

[[nodiscard]] std::vector<Secp256k1Field>
bitsOf(std::uint64_t v, std::size_t n)
{
    std::vector<Secp256k1Field> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
        out.push_back(Secp256k1Field::fromUint64((v >> i) & 1u));
    return out;
}

[[nodiscard]] std::optional<Secp256k1Point>
parsePoint(std::uint8_t const*& p, std::uint8_t const* end)
{
    if (static_cast<std::size_t>(end - p) < Secp256k1Point::kSerializedSize)
        return std::nullopt;
    auto pt = Secp256k1Point::parse(Slice(p, Secp256k1Point::kSerializedSize));
    p += Secp256k1Point::kSerializedSize;
    return pt;
}

[[nodiscard]] std::optional<Secp256k1Scalar>
parseScalar(std::uint8_t const*& p, std::uint8_t const* end)
{
    if (static_cast<std::size_t>(end - p) < Secp256k1Scalar::kSerializedSize)
        return std::nullopt;
    auto s = Secp256k1Scalar::parse(Slice(p, Secp256k1Scalar::kSerializedSize));
    p += Secp256k1Scalar::kSerializedSize;
    return s;
}

void
writePoint(std::uint8_t*& out, Secp256k1Point const& pt)
{
    pt.serialize(out);
    out += Secp256k1Point::kSerializedSize;
}

void
writeScalar(std::uint8_t*& out, Secp256k1Scalar const& s)
{
    s.serialize(out);
    out += Secp256k1Scalar::kSerializedSize;
}

struct IpaProof
{
    std::vector<Secp256k1Point> L;
    std::vector<Secp256k1Point> R;
    std::optional<Secp256k1Scalar> a;
    std::optional<Secp256k1Scalar> b;
};

[[nodiscard]] std::optional<IpaProof>
proveIpa(
    std::vector<Secp256k1Point> G,
    std::vector<Secp256k1Point> H,
    std::vector<Secp256k1Field> a,
    std::vector<Secp256k1Field> b,
    Secp256k1Point const& U,
    CompactTranscript& tr)
{
    IpaProof out;
    while (a.size() > 1)
    {
        auto const n = a.size() / 2;
        std::vector<Secp256k1Field> aLo(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(n));
        std::vector<Secp256k1Field> aHi(a.begin() + static_cast<std::ptrdiff_t>(n), a.end());
        std::vector<Secp256k1Field> bLo(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
        std::vector<Secp256k1Field> bHi(b.begin() + static_cast<std::ptrdiff_t>(n), b.end());
        std::vector<Secp256k1Point> GLo(G.begin(), G.begin() + static_cast<std::ptrdiff_t>(n));
        std::vector<Secp256k1Point> GHi(G.begin() + static_cast<std::ptrdiff_t>(n), G.end());
        std::vector<Secp256k1Point> HLo(H.begin(), H.begin() + static_cast<std::ptrdiff_t>(n));
        std::vector<Secp256k1Point> HHi(H.begin() + static_cast<std::ptrdiff_t>(n), H.end());

        auto const cL = inner(aLo, bHi);
        auto const cR = inner(aHi, bLo);
        auto L = addPoints(msm(GHi, aLo), msm(HLo, bHi));
        if (auto cLU = pointMultiply(U, cL))
            L = addPoints(L, cLU);
        auto R = addPoints(msm(GLo, aHi), msm(HHi, bLo));
        if (auto cRU = pointMultiply(U, cR))
            R = addPoints(R, cRU);
        if (!L || !R)
            return std::nullopt;

        tr.append(*L);
        tr.append(*R);
        auto uS = tr.challenge();
        if (!uS)
            return std::nullopt;
        tr.append(*uS);
        auto const u = Secp256k1Field::fromScalar(*uS);
        auto uInv = fieldInverse(u);
        if (!uInv)
            return std::nullopt;

        std::vector<Secp256k1Field> aN;
        std::vector<Secp256k1Field> bN;
        std::vector<Secp256k1Point> GN;
        std::vector<Secp256k1Point> HN;
        aN.reserve(n);
        bN.reserve(n);
        GN.reserve(n);
        HN.reserve(n);
        for (std::size_t i = 0; i < n; ++i)
        {
            aN.push_back(fieldAdd(fieldMul(aLo[i], u), fieldMul(aHi[i], *uInv)));
            bN.push_back(fieldAdd(fieldMul(bLo[i], *uInv), fieldMul(bHi[i], u)));
            auto gTerm = addPoints(pointMultiply(GLo[i], *uInv), pointMultiply(GHi[i], u));
            auto hTerm = addPoints(pointMultiply(HLo[i], u), pointMultiply(HHi[i], *uInv));
            if (!gTerm || !hTerm)
                return std::nullopt;
            GN.push_back(*gTerm);
            HN.push_back(*hTerm);
        }
        out.L.push_back(*L);
        out.R.push_back(*R);
        a = std::move(aN);
        b = std::move(bN);
        G = std::move(GN);
        H = std::move(HN);
    }
    auto aS = a[0].toScalar();
    auto bS = b[0].toScalar();
    if (!aS || !bS)
        return std::nullopt;
    out.a = *aS;
    out.b = *bS;
    return out;
}

[[nodiscard]] bool
verifyIpa(
    std::vector<Secp256k1Point> const& G,
    std::vector<Secp256k1Point> const& H,
    Secp256k1Point const& P,
    Secp256k1Point const& U,
    IpaProof const& ipa,
    CompactTranscript& tr)
{
    auto const rounds = ipa.L.size();
    if (ipa.R.size() != rounds || !ipa.a || !ipa.b)
        return false;
    std::size_t n = G.size();
    if (n != H.size() || (n >> rounds) != 1)
        return false;

    std::vector<Secp256k1Field> us;
    std::vector<Secp256k1Field> uInvs;
    us.reserve(rounds);
    uInvs.reserve(rounds);
    auto accP = P;
    for (std::size_t j = 0; j < rounds; ++j)
    {
        tr.append(ipa.L[j]);
        tr.append(ipa.R[j]);
        auto uS = tr.challenge();
        if (!uS)
            return false;
        tr.append(*uS);
        auto const u = Secp256k1Field::fromScalar(*uS);
        auto uInv = fieldInverse(u);
        if (!uInv)
            return false;
        us.push_back(u);
        uInvs.push_back(*uInv);
        auto const u2 = fieldMul(u, u);
        auto const uInv2 = fieldMul(*uInv, *uInv);
        auto Lterm = pointMultiply(ipa.L[j], u2);
        auto Rterm = pointMultiply(ipa.R[j], uInv2);
        if (!Lterm || !Rterm)
            return false;
        auto tmp = pointAdd(accP, *Lterm);
        if (!tmp)
            return false;
        tmp = pointAdd(*tmp, *Rterm);
        if (!tmp)
            return false;
        accP = *tmp;
    }

    std::vector<Secp256k1Field> s(n, one());
    for (std::size_t i = 0; i < n; ++i)
    {
        for (std::size_t j = 0; j < rounds; ++j)
        {
            bool const bit = ((i >> (rounds - 1 - j)) & 1u) != 0;
            s[i] = fieldMul(s[i], bit ? us[j] : uInvs[j]);
        }
    }
    std::vector<Secp256k1Field> t(n, one());
    for (std::size_t i = 0; i < n; ++i)
    {
        for (std::size_t j = 0; j < rounds; ++j)
        {
            bool const bit = ((i >> (rounds - 1 - j)) & 1u) != 0;
            t[i] = fieldMul(t[i], bit ? uInvs[j] : us[j]);
        }
    }

    auto Gfin = msm(G, s);
    auto Hfin = msm(H, t);
    if (!Gfin || !Hfin)
        return false;
    auto const aF = Secp256k1Field::fromScalar(*ipa.a);
    auto const bF = Secp256k1Field::fromScalar(*ipa.b);
    auto left = addPoints(pointMultiply(*Gfin, aF), pointMultiply(*Hfin, bF));
    auto abU = pointMultiply(U, fieldMul(aF, bF));
    left = addPoints(left, abU);
    return left && *left == accP;
}

[[nodiscard]] Secp256k1Field
deltaYZ(Secp256k1Field const& y, Secp256k1Field const& z, std::size_t m)
{
    auto const nTot = kN * m;
    auto const yP = powers(y, nTot);
    auto sumY = Secp256k1Field::zero();
    for (auto const& yi : yP)
        sumY = fieldAdd(sumY, yi);
    auto const twoNminus1 = Secp256k1Field::fromUint64(~std::uint64_t{0});
    // Paper: Σ_{j=1}^m z^{j+2} ⟨1^n, 2^n⟩ — first term is z^3.
    auto zPow = fieldMul(fieldMul(z, z), z);
    auto weighted = Secp256k1Field::zero();
    for (std::size_t j = 0; j < m; ++j)
    {
        weighted = fieldAdd(weighted, zPow);
        zPow = fieldMul(zPow, z);
    }
    auto const term2 = fieldMul(weighted, twoNminus1);
    auto const zMinusZ2 = fieldSub(z, fieldMul(z, z));
    return fieldSub(fieldMul(zMinusZ2, sumY), term2);
}

[[nodiscard]] std::vector<Secp256k1Field>
rangeOffset(Secp256k1Field const& z, std::size_t m)
{
    auto const nTot = kN * m;
    auto const two = twoPowers(kN);
    std::vector<Secp256k1Field> out(nTot, Secp256k1Field::zero());
    auto zPow = fieldMul(z, z);  // z^2 for first value
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < kN; ++i)
            out[j * kN + i] = fieldMul(zPow, two[i]);
        zPow = fieldMul(zPow, z);
    }
    return out;
}

struct RangeProofParts
{
    Secp256k1Point A;
    Secp256k1Point S;
    Secp256k1Point T1;
    Secp256k1Point T2;
    Secp256k1Scalar tauX;
    Secp256k1Scalar mu;
    Secp256k1Scalar tHat;
    IpaProof ipa;
};

[[nodiscard]] std::optional<RangeProofParts>
proveRange(
    std::vector<std::uint64_t> const& values,
    std::vector<Secp256k1Scalar> const& blinds,
    std::vector<Secp256k1Point> const& Vs,
    std::string_view domain)
{
    auto const m = values.size();
    if (m == 0 || m > 2 || blinds.size() != m || Vs.size() != m)
        return std::nullopt;
    auto const nTot = kN * m;
    auto const& gens = generators();
    std::vector<Secp256k1Point> G(
        gens.g.begin(), gens.g.begin() + static_cast<std::ptrdiff_t>(nTot));
    std::vector<Secp256k1Point> H(
        gens.h.begin(), gens.h.begin() + static_cast<std::ptrdiff_t>(nTot));

    std::vector<Secp256k1Field> aL;
    aL.reserve(nTot);
    for (auto v : values)
    {
        auto bits = bitsOf(v, kN);
        aL.insert(aL.end(), bits.begin(), bits.end());
    }
    std::vector<Secp256k1Field> aR;
    aR.reserve(nTot);
    for (auto const& bit : aL)
        aR.push_back(fieldSub(bit, one()));

    auto alpha = sampleScalar();
    auto rho = sampleScalar();
    if (!alpha || !rho)
        return std::nullopt;

    std::vector<Secp256k1Field> sL;
    std::vector<Secp256k1Field> sR;
    sL.reserve(nTot);
    sR.reserve(nTot);
    for (std::size_t i = 0; i < nTot; ++i)
    {
        auto sl = sampleScalar();
        auto sr = sampleScalar();
        if (!sl || !sr)
            return std::nullopt;
        sL.push_back(Secp256k1Field::fromScalar(*sl));
        sR.push_back(Secp256k1Field::fromScalar(*sr));
    }

    auto A = pointMultiply(pedersenH(), *alpha);
    A = addPoints(A, msm(G, aL));
    A = addPoints(A, msm(H, aR));
    auto S = pointMultiply(pedersenH(), *rho);
    S = addPoints(S, msm(G, sL));
    S = addPoints(S, msm(H, sR));
    if (!A || !S)
        return std::nullopt;

    CompactTranscript tr;
    tr.appendDomainTag(domain);
    for (auto const& V : Vs)
        tr.append(V);
    tr.append(*A);
    tr.append(*S);
    auto yS = tr.challenge();
    if (!yS)
        return std::nullopt;
    tr.append(*yS);
    auto zS = tr.challenge();
    if (!zS)
        return std::nullopt;
    tr.append(*zS);

    auto const y = Secp256k1Field::fromScalar(*yS);
    auto const z = Secp256k1Field::fromScalar(*zS);
    auto const yP = powers(y, nTot);
    auto const l0 = vecAdd(aL, vecScale(ones(nTot), fieldNegate(z)));
    auto const l1 = sL;
    auto const aRplusZ = vecAdd(aR, vecScale(ones(nTot), z));
    auto const r0 = vecAdd(hadamard(yP, aRplusZ), rangeOffset(z, m));
    auto const r1 = hadamard(yP, sR);

    auto const t0 = inner(l0, r0);
    auto const t1 = fieldAdd(inner(l0, r1), inner(l1, r0));
    auto const t2 = inner(l1, r1);

    {
        auto zPow = fieldMul(z, z);
        auto t0Expect = deltaYZ(y, z, m);
        for (std::size_t j = 0; j < m; ++j)
        {
            t0Expect = fieldAdd(t0Expect, fieldMul(zPow, Secp256k1Field::fromUint64(values[j])));
            zPow = fieldMul(zPow, z);
        }
        if (t0.serialize() != t0Expect.serialize())
            return std::nullopt;
    }

    auto tau1 = sampleScalar();
    auto tau2 = sampleScalar();
    if (!tau1 || !tau2)
        return std::nullopt;
    auto T1 = pedersenCommit(t1, *tau1);
    auto T2 = pedersenCommit(t2, *tau2);
    if (!T1 || !T2)
        return std::nullopt;

    tr.append(*T1);
    tr.append(*T2);
    auto xS = tr.challenge();
    if (!xS)
        return std::nullopt;
    tr.append(*xS);
    auto const x = Secp256k1Field::fromScalar(*xS);

    auto l = vecAdd(l0, vecScale(l1, x));
    auto r = vecAdd(r0, vecScale(r1, x));
    auto const tHatF = inner(l, r);

    // τ_x = τ1 x + τ2 x^2 + Σ_j z^{j+1} γ_j  (j from 1: z^2 γ1 + z^3 γ2)
    auto tauAcc = fieldAdd(
        fieldMul(Secp256k1Field::fromScalar(*tau1), x),
        fieldMul(Secp256k1Field::fromScalar(*tau2), fieldMul(x, x)));
    auto zPow = fieldMul(z, z);
    for (std::size_t j = 0; j < m; ++j)
    {
        tauAcc = fieldAdd(tauAcc, fieldMul(zPow, Secp256k1Field::fromScalar(blinds[j])));
        zPow = fieldMul(zPow, z);
    }
    auto muF =
        fieldAdd(Secp256k1Field::fromScalar(*alpha), fieldMul(Secp256k1Field::fromScalar(*rho), x));
    auto tauX = tauAcc.toScalar();
    auto mu = muF.toScalar();
    auto tHat = tHatF.toScalar();
    if (!tauX || !mu || !tHat)
        return std::nullopt;

    auto yInv = fieldInverse(y);
    if (!yInv)
        return std::nullopt;
    auto yInvP = powers(*yInv, nTot);
    std::vector<Secp256k1Point> Hp;
    Hp.reserve(nTot);
    for (std::size_t i = 0; i < nTot; ++i)
    {
        auto hi = pointMultiply(H[i], yInvP[i]);
        if (!hi)
            return std::nullopt;
        Hp.push_back(*hi);
    }

    auto ipa = proveIpa(G, Hp, l, r, gens.u, tr);
    if (!ipa)
        return std::nullopt;

    return RangeProofParts{*A, *S, *T1, *T2, *tauX, *mu, *tHat, *ipa};
}

[[nodiscard]] bool
verifyRange(
    std::vector<Secp256k1Point> const& Vs,
    RangeProofParts const& proof,
    std::string_view domain)
{
    auto const m = Vs.size();
    if (m == 0 || m > 2)
        return false;
    auto const nTot = kN * m;
    auto const rounds = (m == 1) ? kLogN : kLogAgg;
    if (proof.ipa.L.size() != rounds || proof.ipa.R.size() != rounds)
        return false;

    auto const& gens = generators();
    std::vector<Secp256k1Point> G(
        gens.g.begin(), gens.g.begin() + static_cast<std::ptrdiff_t>(nTot));
    std::vector<Secp256k1Point> H(
        gens.h.begin(), gens.h.begin() + static_cast<std::ptrdiff_t>(nTot));

    CompactTranscript tr;
    tr.appendDomainTag(domain);
    for (auto const& V : Vs)
        tr.append(V);
    tr.append(proof.A);
    tr.append(proof.S);
    auto yS = tr.challenge();
    if (!yS)
        return false;
    tr.append(*yS);
    auto zS = tr.challenge();
    if (!zS)
        return false;
    tr.append(*zS);
    tr.append(proof.T1);
    tr.append(proof.T2);
    auto xS = tr.challenge();
    if (!xS)
        return false;
    tr.append(*xS);

    auto const y = Secp256k1Field::fromScalar(*yS);
    auto const z = Secp256k1Field::fromScalar(*zS);
    auto const x = Secp256k1Field::fromScalar(*xS);
    auto const tHat = Secp256k1Field::fromScalar(proof.tHat);
    auto const tauX = Secp256k1Field::fromScalar(proof.tauX);
    auto const mu = Secp256k1Field::fromScalar(proof.mu);

    auto const dlt = deltaYZ(y, z, m);
    auto lhs = pedersenCommit(tHat, proof.tauX);
    auto rhs = generatorMultiply(dlt);
    auto zPow = fieldMul(z, z);
    for (std::size_t j = 0; j < m; ++j)
    {
        auto Vterm = pointMultiply(Vs[j], zPow);
        rhs = addPoints(rhs, Vterm);
        zPow = fieldMul(zPow, z);
    }
    rhs = addPoints(rhs, pointMultiply(proof.T1, x));
    rhs = addPoints(rhs, pointMultiply(proof.T2, fieldMul(x, x)));
    if (!lhs || !rhs || !(*lhs == *rhs))
        return false;

    auto yInv = fieldInverse(y);
    if (!yInv)
        return false;
    auto const yP = powers(y, nTot);
    auto const yInvP = powers(*yInv, nTot);
    std::vector<Secp256k1Point> Hp;
    Hp.reserve(nTot);
    std::vector<Secp256k1Field> hCoeff;
    hCoeff.reserve(nTot);
    auto const off = rangeOffset(z, m);
    for (std::size_t i = 0; i < nTot; ++i)
    {
        auto hi = pointMultiply(H[i], yInvP[i]);
        if (!hi)
            return false;
        Hp.push_back(*hi);
        hCoeff.push_back(fieldAdd(fieldMul(z, yP[i]), off[i]));
    }

    auto P = addPoints(proof.A, pointMultiply(proof.S, x));
    P = addPoints(P, msm(G, vecScale(ones(nTot), fieldNegate(z))));
    P = addPoints(P, msm(Hp, hCoeff));
    P = addPoints(P, pointMultiply(pedersenH(), fieldNegate(mu)));
    P = addPoints(P, pointMultiply(gens.u, tHat));
    if (!P)
        return false;

    CompactTranscript ipaTr = tr;
    return verifyIpa(G, Hp, *P, gens.u, proof.ipa, ipaTr);
}

template <std::size_t N>
[[nodiscard]] std::optional<std::array<std::uint8_t, N>>
serializeProof(RangeProofParts const& p, std::size_t rounds)
{
    if (p.ipa.L.size() != rounds || p.ipa.R.size() != rounds)
        return std::nullopt;
    std::array<std::uint8_t, N> out{};
    auto* w = out.data();
    writePoint(w, p.A);
    writePoint(w, p.S);
    writePoint(w, p.T1);
    writePoint(w, p.T2);
    writeScalar(w, p.tauX);
    writeScalar(w, p.mu);
    writeScalar(w, p.tHat);
    for (auto const& L : p.ipa.L)
        writePoint(w, L);
    for (auto const& R : p.ipa.R)
        writePoint(w, R);
    if (!p.ipa.a || !p.ipa.b)
        return std::nullopt;
    writeScalar(w, *p.ipa.a);
    writeScalar(w, *p.ipa.b);
    if (static_cast<std::size_t>(w - out.data()) != N)
        return std::nullopt;
    return out;
}

[[nodiscard]] std::optional<RangeProofParts>
parseProof(Slice proof, std::size_t rounds)
{
    auto const nPts = 4 + 2 * rounds;
    auto const nSc = 5;
    auto const want =
        nPts * Secp256k1Point::kSerializedSize + nSc * Secp256k1Scalar::kSerializedSize;
    if (proof.size() != want)
        return std::nullopt;
    auto const* p = proof.data();
    auto const* end = p + proof.size();
    auto A = parsePoint(p, end);
    auto S = parsePoint(p, end);
    auto T1 = parsePoint(p, end);
    auto T2 = parsePoint(p, end);
    auto tauX = parseScalar(p, end);
    auto mu = parseScalar(p, end);
    auto tHat = parseScalar(p, end);
    if (!A || !S || !T1 || !T2 || !tauX || !mu || !tHat)
        return std::nullopt;
    IpaProof ipa;
    ipa.L.reserve(rounds);
    ipa.R.reserve(rounds);
    for (std::size_t i = 0; i < rounds; ++i)
    {
        auto L = parsePoint(p, end);
        if (!L)
            return std::nullopt;
        ipa.L.push_back(*L);
    }
    for (std::size_t i = 0; i < rounds; ++i)
    {
        auto R = parsePoint(p, end);
        if (!R)
            return std::nullopt;
        ipa.R.push_back(*R);
    }
    auto a = parseScalar(p, end);
    auto b = parseScalar(p, end);
    if (!a || !b || p != end)
        return std::nullopt;
    ipa.a = std::move(a);
    ipa.b = std::move(b);
    return RangeProofParts{*A, *S, *T1, *T2, *tauX, *mu, *tHat, std::move(ipa)};
}

}  // namespace

std::optional<std::array<std::uint8_t, kSingleBulletproofSize>>
proveRange64(std::uint64_t value, Secp256k1Scalar const& blinding, Secp256k1Point const& commitment)
{
    auto const expect = pedersenCommit(value, blinding);
    if (!expect || !(*expect == commitment))
        return std::nullopt;
    auto parts = proveRange({value}, {blinding}, {commitment}, kTagSingle);
    if (!parts)
        return std::nullopt;
    return serializeProof<kSingleBulletproofSize>(*parts, kLogN);
}

bool
verifyRange64(Secp256k1Point const& commitment, Slice proof)
{
    auto parts = parseProof(proof, kLogN);
    if (!parts)
        return false;
    return verifyRange({commitment}, *parts, kTagSingle);
}

std::optional<std::array<std::uint8_t, kAggregatedBulletproofSize>>
proveRange64Aggregated(
    std::uint64_t value1,
    Secp256k1Scalar const& blinding1,
    Secp256k1Point const& commitment1,
    std::uint64_t value2,
    Secp256k1Scalar const& blinding2,
    Secp256k1Point const& commitment2)
{
    auto const e1 = pedersenCommit(value1, blinding1);
    auto const e2 = pedersenCommit(value2, blinding2);
    if (!e1 || !e2 || !(*e1 == commitment1) || !(*e2 == commitment2))
        return std::nullopt;
    auto parts =
        proveRange({value1, value2}, {blinding1, blinding2}, {commitment1, commitment2}, kTagAgg);
    if (!parts)
        return std::nullopt;
    return serializeProof<kAggregatedBulletproofSize>(*parts, kLogAgg);
}

bool
verifyRange64Aggregated(
    Secp256k1Point const& commitment1,
    Secp256k1Point const& commitment2,
    Slice proof)
{
    auto parts = parseProof(proof, kLogAgg);
    if (!parts)
        return false;
    return verifyRange({commitment1, commitment2}, *parts, kTagAgg);
}

}  // namespace xrpl
