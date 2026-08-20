#include <xrpl/protocol/Confidential.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/protocol/detail/secp256k1.h>

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace xrpl {
namespace {

constexpr std::size_t kSc = 32;
constexpr std::size_t kPt = kConfidentialPubKeyLength;
constexpr std::size_t kBits = 64;

uint256 const&
orderN()
{
    static uint256 const n = [] {
        uint256 x;
        if (!x.parseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
            logicError("orderN");
        return x;
    }();
    return n;
}

bool
scZero(unsigned char const* s)
{
    unsigned char a = 0;
    for (int i = 0; i < 32; ++i)
        a |= s[i];
    return a == 0;
}

void
subBE(uint256& x, uint256 const& y)
{
    unsigned borrow = 0;
    for (int i = 31; i >= 0; --i)
    {
        unsigned const lhs = x.data()[i];
        unsigned const rhs = y.data()[i] + borrow;
        if (lhs < rhs)
        {
            x.data()[i] = static_cast<unsigned char>(lhs + 256u - rhs);
            borrow = 1;
        }
        else
        {
            x.data()[i] = static_cast<unsigned char>(lhs - rhs);
            borrow = 0;
        }
    }
}

void
addBE(uint256& x, uint256 const& y)
{
    unsigned carry = 0;
    for (int i = 31; i >= 0; --i)
    {
        unsigned const sum = x.data()[i] + y.data()[i] + carry;
        x.data()[i] = static_cast<unsigned char>(sum & 0xffu);
        carry = sum >> 8;
    }
}

uint256
reduceChallenge(uint256 x)
{
    auto const& n = orderN();
    if (x >= n)
        subBE(x, n);
    if (!x)
        x = uint256{std::uint64_t{1}};
    return x;
}

uint256
modN(uint256 x)
{
    auto const& n = orderN();
    while (x >= n)
        subBE(x, n);
    return x;
}

uint256
addM(uint256 a, uint256 b)
{
    if (!a)
        return b;
    if (!b)
        return a;
    // a := a+b mod n. Failure means result is 0 (a+b = n).
    if (secp256k1_ec_seckey_tweak_add(secp256k1Context(), a.data(), b.data()) != 1)
        return uint256{};
    return a;
}

uint256
negM(uint256 a)
{
    if (!a)
        return a;
    uint256 n = orderN();
    subBE(n, a);
    return n;
}

uint256
subM(uint256 a, uint256 b)
{
    return addM(a, negM(b));
}

uint256
mulM(uint256 const& a, uint256 const& b)
{
    if (!a || !b)
        return uint256{};
    // a := a*b mod n. Result 0 is impossible for nonzero prime-order field elements.
    uint256 r = a;
    if (secp256k1_ec_seckey_tweak_mul(secp256k1Context(), r.data(), b.data()) != 1)
        return uint256{};
    return r;
}

uint256
invM(uint256 a)
{
    if (!a)
        return uint256{};
    uint256 e = orderN();
    subBE(e, uint256{std::uint64_t{2}});
    uint256 base = a;
    uint256 res{std::uint64_t{1}};
    for (int i = 255; i >= 0; --i)
    {
        res = mulM(res, res);
        if ((e.data()[i / 8] >> (7 - (i % 8))) & 1u)
            res = mulM(res, base);
    }
    return res;
}

void
u64ToSc(std::uint64_t v, unsigned char out[32])
{
    std::memset(out, 0, 32);
    for (int i = 0; i < 8; ++i)
        out[31 - i] = static_cast<unsigned char>(v >> (8 * i));
}

uint256
u64ToSc(std::uint64_t v)
{
    uint256 o;
    u64ToSc(v, o.data());
    return o;
}

void
be32Enc(std::uint32_t v, unsigned char o[4])
{
    o[0] = static_cast<unsigned char>(v >> 24);
    o[1] = static_cast<unsigned char>(v >> 16);
    o[2] = static_cast<unsigned char>(v >> 8);
    o[3] = static_cast<unsigned char>(v);
}

uint256
randSc()
{
    std::array<unsigned char, 32> k{};
    auto& rng = cryptoPrng();
    do
    {
        rng(k.data(), k.size());
    } while (secp256k1_ec_seckey_verify(secp256k1Context(), k.data()) != 1);
    uint256 o;
    std::memcpy(o.data(), k.data(), 32);
    return o;
}

bool
parsePt(Slice const& b, secp256k1_pubkey& o)
{
    return b.size() == kPt &&
        secp256k1_ec_pubkey_parse(secp256k1Context(), &o, b.data(), b.size()) == 1;
}

bool
serPt(secp256k1_pubkey const& pk, unsigned char o[kPt])
{
    std::size_t len = kPt;
    return secp256k1_ec_pubkey_serialize(
               secp256k1Context(), o, &len, &pk, SECP256K1_EC_COMPRESSED) == 1 &&
        len == kPt;
}

std::optional<secp256k1_pubkey>
mkPt(unsigned char const* sc)
{
    if (scZero(sc))
        return std::nullopt;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &pk, sc) != 1)
        return std::nullopt;
    return pk;
}

std::optional<secp256k1_pubkey>
comb(secp256k1_pubkey const& a, secp256k1_pubkey const& b)
{
    secp256k1_pubkey const* ins[2] = {&a, &b};
    secp256k1_pubkey o;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &o, ins, 2) != 1)
        return std::nullopt;
    return o;
}

std::optional<secp256k1_pubkey>
combN(std::vector<secp256k1_pubkey> const& pts)
{
    if (pts.empty())
        return std::nullopt;
    if (pts.size() == 1)
        return pts[0];
    std::vector<secp256k1_pubkey const*> ins;
    ins.reserve(pts.size());
    for (auto const& p : pts)
        ins.push_back(&p);
    secp256k1_pubkey o;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &o, ins.data(), ins.size()) != 1)
        return std::nullopt;
    return o;
}

std::optional<secp256k1_pubkey>
tmul(secp256k1_pubkey pk, unsigned char const* sc)
{
    if (scZero(sc))
        return std::nullopt;
    if (secp256k1_ec_pubkey_tweak_mul(secp256k1Context(), &pk, sc) != 1)
        return std::nullopt;
    return pk;
}

std::optional<secp256k1_pubkey>
negPk(secp256k1_pubkey pk)
{
    if (secp256k1_ec_pubkey_negate(secp256k1Context(), &pk) != 1)
        return std::nullopt;
    return pk;
}

std::optional<secp256k1_pubkey>
psub(secp256k1_pubkey const& a, secp256k1_pubkey const& b)
{
    auto nb = negPk(b);
    if (!nb)
        return std::nullopt;
    return comb(a, *nb);
}

bool
parseCt(Slice const& ct, secp256k1_pubkey& r, secp256k1_pubkey& s)
{
    if (ct.size() != kConfidentialCiphertextLength)
        return false;
    return parsePt(Slice(ct.data(), kPt), r) && parsePt(Slice(ct.data() + kPt, kPt), s);
}

void
Hpt(sha512_half_hasher& h, secp256k1_pubkey const& pk)
{
    unsigned char b[kPt];
    if (!serPt(pk, b))
        logicError("Hpt");
    h(b, sizeof(b));
}

void
Hraw(sha512_half_hasher& h, void const* p, std::size_t n)
{
    h(p, n);
}

void
Hsc(sha512_half_hasher& h, uint256 const& s)
{
    h(s.data(), 32);
}

std::optional<secp256k1_pubkey>
hashToCurve(Slice const& domain)
{
    sha512_half_hasher h;
    h(domain.data(), domain.size());
    uint256 x = static_cast<uint256>(h);
    for (std::uint32_t t = 0; t < (1u << 20); ++t)
    {
        unsigned char enc[kPt];
        enc[0] = 0x02;
        std::memcpy(enc + 1, x.data(), 32);
        secp256k1_pubkey pk;
        if (secp256k1_ec_pubkey_parse(secp256k1Context(), &pk, enc, sizeof(enc)) == 1)
            return pk;
        enc[0] = 0x03;
        if (secp256k1_ec_pubkey_parse(secp256k1Context(), &pk, enc, sizeof(enc)) == 1)
            return pk;
        ++x;
    }
    return std::nullopt;
}

secp256k1_pubkey const&
pedH()
{
    static secp256k1_pubkey const kH = [] {
        static constexpr char const d[] = "XLS-0096/Pedersen/H";
        auto p = hashToCurve(Slice(d, sizeof(d) - 1));
        if (!p)
            logicError("pedH");
        return *p;
    }();
    return kH;
}

std::optional<secp256k1_pubkey>
bpGen(char const* prefix, std::size_t prefixLen, std::uint32_t index)
{
    std::vector<unsigned char> dom(prefixLen + 4);
    std::memcpy(dom.data(), prefix, prefixLen);
    be32Enc(index, dom.data() + prefixLen);
    return hashToCurve(Slice(dom.data(), dom.size()));
}

std::optional<secp256k1_pubkey>
pedersenPoint(std::uint64_t v, uint256 const& r)
{
    if (!isConfidentialScalar(r))
        return std::nullopt;
    auto rH = tmul(pedH(), r.data());
    if (!rH)
        return std::nullopt;
    if (v == 0)
        return *rH;
    auto vG = mkPt(u64ToSc(v).data());
    if (!vG)
        return std::nullopt;
    return comb(*vG, *rH);
}

// MSM; all-zero scalars => nullopt (identity / omit term).
std::optional<secp256k1_pubkey>
msm(std::vector<secp256k1_pubkey> const& pts, std::vector<uint256> const& sc)
{
    if (pts.size() != sc.size())
        return std::nullopt;
    std::vector<secp256k1_pubkey> terms;
    for (std::size_t i = 0; i < pts.size(); ++i)
    {
        if (!sc[i])
            continue;
        auto t = tmul(pts[i], sc[i].data());
        if (!t)
            return std::nullopt;
        terms.push_back(*t);
    }
    if (terms.empty())
        return std::nullopt;
    return combN(terms);
}

std::optional<secp256k1_pubkey>
addOpt(std::optional<secp256k1_pubkey> a, std::optional<secp256k1_pubkey> b)
{
    if (!a)
        return b;
    if (!b)
        return a;
    return comb(*a, *b);
}

uint256
resp(uint256 const& k, uint256 const& c, uint256 const& w)
{
    return addM(k, mulM(c, w));
}


//------------------------------------------------------------------------------
// Public helpers used below
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Bulletproof
//------------------------------------------------------------------------------

constexpr char const kBpG[] = "XLS-0096/BP/G/";
constexpr char const kBpH[] = "XLS-0096/BP/H/";
constexpr char const kBpU[] = "XLS-0096/BP/U/";
constexpr char const kBpDom[] = "XLS-0096/Bulletproof";

std::size_t
bpRounds(std::size_t n)
{
    std::size_t r = 0;
    while (n > 1)
    {
        n >>= 1;
        ++r;
    }
    return r;
}

bool
loadGens(
    std::size_t n,
    std::vector<secp256k1_pubkey>& G,
    std::vector<secp256k1_pubkey>& H,
    secp256k1_pubkey& U)
{
    G.resize(n);
    H.resize(n);
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(n); ++i)
    {
        auto g = bpGen(kBpG, sizeof(kBpG) - 1, i);
        auto h = bpGen(kBpH, sizeof(kBpH) - 1, i);
        if (!g || !h)
            return false;
        G[i] = *g;
        H[i] = *h;
    }
    auto u = bpGen(kBpU, sizeof(kBpU) - 1, 0);
    if (!u)
        return false;
    U = *u;
    return true;
}

bool
ipaLR(
    secp256k1_pubkey& L,
    secp256k1_pubkey& R,
    std::vector<uint256> const& aLo,
    std::vector<uint256> const& aHi,
    std::vector<uint256> const& bLo,
    std::vector<uint256> const& bHi,
    std::vector<secp256k1_pubkey> const& GLo,
    std::vector<secp256k1_pubkey> const& GHi,
    std::vector<secp256k1_pubkey> const& HLo,
    std::vector<secp256k1_pubkey> const& HHi,
    secp256k1_pubkey const& U,
    uint256 const& ux,
    std::size_t half)
{
    auto L1 = msm(GHi, aLo);
    auto L2 = msm(HLo, bHi);
    auto Ls = addOpt(L1, L2);
    if (!Ls)
        return false;
    uint256 dotL;
    for (std::size_t i = 0; i < half; ++i)
        dotL = addM(dotL, mulM(aLo[i], bHi[i]));
    auto cL = mulM(dotL, ux);
    if (cL.isNonZero())
    {
        auto ut = tmul(U, cL.data());
        if (!ut)
            return false;
        Ls = comb(*Ls, *ut);
        if (!Ls)
            return false;
    }
    L = *Ls;

    auto R1 = msm(GLo, aHi);
    auto R2 = msm(HHi, bLo);
    auto Rs = addOpt(R1, R2);
    if (!Rs)
        return false;
    uint256 dotR;
    for (std::size_t i = 0; i < half; ++i)
        dotR = addM(dotR, mulM(aHi[i], bLo[i]));
    auto cR = mulM(dotR, ux);
    if (cR.isNonZero())
    {
        auto ut = tmul(U, cR.data());
        if (!ut)
            return false;
        Rs = comb(*Rs, *ut);
        if (!Rs)
            return false;
    }
    R = *Rs;
    return true;
}

bool
ipaFoldStep(
    std::vector<uint256>& a,
    std::vector<uint256>& b,
    std::vector<secp256k1_pubkey>& G,
    std::vector<secp256k1_pubkey>& H,
    std::size_t half,
    uint256 const& u,
    uint256 const& uInv)
{
    for (std::size_t i = 0; i < half; ++i)
    {
        a[i] = addM(mulM(a[i], u), mulM(a[i + half], uInv));
        b[i] = addM(mulM(b[i], uInv), mulM(b[i + half], u));
        auto gL = tmul(G[i], uInv.data());
        auto gR = tmul(G[i + half], u.data());
        if (!gL || !gR)
            return false;
        auto g = comb(*gL, *gR);
        if (!g)
            return false;
        G[i] = *g;
        auto hL = tmul(H[i], u.data());
        auto hR = tmul(H[i + half], uInv.data());
        if (!hL || !hR)
            return false;
        auto hh = comb(*hL, *hR);
        if (!hh)
            return false;
        H[i] = *hh;
    }
    a.resize(half);
    b.resize(half);
    G.resize(half);
    H.resize(half);
    return true;
}

std::optional<Buffer>
bpProve(
    std::vector<std::uint64_t> const& values,
    std::vector<uint256> const& blinds,
    Slice const& tr)
{
    std::size_t const m = values.size();
    if (m == 0 || m > 4 || blinds.size() != m)
        return std::nullopt;
    std::size_t const n = kBits * m;
    if ((n & (n - 1)) != 0)
        return std::nullopt;
    for (auto const& b : blinds)
        if (!isConfidentialScalar(b))
            return std::nullopt;

    std::size_t const rounds = bpRounds(n);
    std::vector<secp256k1_pubkey> G, Hv;
    secp256k1_pubkey U;
    if (!loadGens(n, G, Hv, U))
        return std::nullopt;

    uint256 const one{std::uint64_t{1}};
    uint256 const m1 = negM(one);

    std::vector<uint256> aL(n), aR(n), sL(n), sR(n);
    for (std::size_t j = 0; j < m; ++j)
    {
        std::uint64_t v = values[j];
        for (std::size_t i = 0; i < kBits; ++i)
        {
            std::size_t const k = j * kBits + i;
            if ((v >> i) & 1ull)
            {
                aL[k] = one;
                aR[k] = uint256{};
            }
            else
            {
                aL[k] = uint256{};
                aR[k] = m1;
            }
            sL[k] = randSc();
            sR[k] = randSc();
        }
    }

    uint256 alpha = randSc();
    uint256 rho = randSc();
    auto A = addOpt(tmul(pedH(), alpha.data()), addOpt(msm(G, aL), msm(Hv, aR)));
    auto S = addOpt(tmul(pedH(), rho.data()), addOpt(msm(G, sL), msm(Hv, sR)));
    if (!A || !S)
        return std::nullopt;

    std::vector<secp256k1_pubkey> V(m);
    for (std::size_t j = 0; j < m; ++j)
    {
        auto vj = pedersenPoint(values[j], blinds[j]);
        if (!vj)
            return std::nullopt;
        V[j] = *vj;
    }

    sha512_half_hasher hy;
    Hraw(hy, kBpDom, sizeof(kBpDom) - 1);
    unsigned char tmp4[4];
    be32Enc(static_cast<std::uint32_t>(n), tmp4);
    Hraw(hy, tmp4, 4);
    be32Enc(static_cast<std::uint32_t>(m), tmp4);
    Hraw(hy, tmp4, 4);
    for (auto const& vj : V)
        Hpt(hy, vj);
    Hpt(hy, *A);
    Hpt(hy, *S);
    Hraw(hy, tr.data(), tr.size());
    uint256 y = reduceChallenge(static_cast<uint256>(hy));

    sha512_half_hasher hz;
    Hraw(hz, kBpDom, sizeof(kBpDom) - 1);
    Hsc(hz, y);
    Hpt(hz, *A);
    Hpt(hz, *S);
    Hraw(hz, tr.data(), tr.size());
    uint256 z = reduceChallenge(static_cast<uint256>(hz));
    uint256 zNeg = negM(z);

    std::vector<uint256> yPow(n);
    uint256 yp = one;
    for (std::size_t k = 0; k < n; ++k)
    {
        yPow[k] = yp;
        yp = mulM(yp, y);
    }
    std::vector<uint256> zJ2(m);
    uint256 zj = mulM(z, z);
    for (std::size_t j = 0; j < m; ++j)
    {
        zJ2[j] = zj;
        zj = mulM(zj, z);
    }

    std::vector<uint256> l0(n), r0(n), r1(n);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < kBits; ++i)
        {
            std::size_t const k = j * kBits + i;
            l0[k] = addM(aL[k], zNeg);
            uint256 twoI = u64ToSc(1ull << i);
            r0[k] = addM(mulM(yPow[k], addM(aR[k], z)), mulM(zJ2[j], twoI));
            r1[k] = mulM(sR[k], yPow[k]);
        }
    }

    uint256 t1, t2;
    for (std::size_t k = 0; k < n; ++k)
    {
        t1 = addM(t1, mulM(l0[k], r1[k]));
        t1 = addM(t1, mulM(sL[k], r0[k]));
        t2 = addM(t2, mulM(sL[k], r1[k]));
    }
    uint256 tau1 = randSc();
    uint256 tau2 = randSc();
    auto mkT = [&](uint256 const& t, uint256 const& tau) -> std::optional<secp256k1_pubkey> {
        auto th = tmul(pedH(), tau.data());
        if (!th)
            return std::nullopt;
        if (!t)
            return *th;
        auto tg = mkPt(t.data());
        if (!tg)
            return std::nullopt;
        return comb(*tg, *th);
    };
    auto T1 = mkT(t1, tau1);
    auto T2 = mkT(t2, tau2);
    if (!T1 || !T2)
        return std::nullopt;

    sha512_half_hasher hx;
    Hpt(hx, *A);
    Hpt(hx, *S);
    Hsc(hx, y);
    Hsc(hx, z);
    Hpt(hx, *T1);
    Hpt(hx, *T2);
    Hraw(hx, tr.data(), tr.size());
    uint256 x = reduceChallenge(static_cast<uint256>(hx));

    std::vector<uint256> l = l0, rv = r0;
    for (std::size_t k = 0; k < n; ++k)
    {
        l[k] = addM(l[k], mulM(sL[k], x));
        rv[k] = addM(rv[k], mulM(r1[k], x));
    }
    uint256 tHat;
    for (std::size_t k = 0; k < n; ++k)
        tHat = addM(tHat, mulM(l[k], rv[k]));

    uint256 x2 = mulM(x, x);
    uint256 tauX = addM(mulM(tau2, x2), mulM(tau1, x));
    for (std::size_t j = 0; j < m; ++j)
        tauX = addM(tauX, mulM(zJ2[j], blinds[j]));
    uint256 mu = addM(alpha, mulM(rho, x));

    sha512_half_hasher hipa;
    Hpt(hipa, *A);
    Hpt(hipa, *S);
    Hpt(hipa, *T1);
    Hpt(hipa, *T2);
    Hsc(hipa, y);
    Hsc(hipa, z);
    Hsc(hipa, x);
    Hsc(hipa, tHat);
    Hraw(hipa, tr.data(), tr.size());
    uint256 ipaSeed = static_cast<uint256>(hipa);

    sha512_half_hasher hux;
    Hsc(hux, ipaSeed);
    Hsc(hux, tHat);
    uint256 ux = reduceChallenge(static_cast<uint256>(hux));

    uint256 yInv = invM(y);
    if (!yInv)
        return std::nullopt;
    std::vector<secp256k1_pubkey> Hp(n);
    uint256 yInvPow = one;
    for (std::size_t k = 0; k < n; ++k)
    {
        auto hp = tmul(Hv[k], yInvPow.data());
        if (!hp)
            return std::nullopt;
        Hp[k] = *hp;
        yInvPow = mulM(yInvPow, yInv);
    }

    std::vector<secp256k1_pubkey> Lr(rounds), Rr(rounds);
    std::vector<uint256> a = l, b = rv;
    std::vector<secp256k1_pubkey> Gw = G, Hw = Hp;
    uint256 last = ipaSeed;
    std::size_t cur = n;
    for (std::size_t round = 0; round < rounds; ++round)
    {
        std::size_t half = cur / 2;
        std::vector<uint256> aLo(a.begin(), a.begin() + half);
        std::vector<uint256> aHi(a.begin() + half, a.begin() + cur);
        std::vector<uint256> bLo(b.begin(), b.begin() + half);
        std::vector<uint256> bHi(b.begin() + half, b.begin() + cur);
        std::vector<secp256k1_pubkey> GLo(Gw.begin(), Gw.begin() + half);
        std::vector<secp256k1_pubkey> GHi(Gw.begin() + half, Gw.begin() + cur);
        std::vector<secp256k1_pubkey> HLo(Hw.begin(), Hw.begin() + half);
        std::vector<secp256k1_pubkey> HHi(Hw.begin() + half, Hw.begin() + cur);
        if (!ipaLR(Lr[round], Rr[round], aLo, aHi, bLo, bHi, GLo, GHi, HLo, HHi, U, ux, half))
            return std::nullopt;
        sha512_half_hasher hu;
        Hsc(hu, last);
        Hpt(hu, Lr[round]);
        Hpt(hu, Rr[round]);
        uint256 u = reduceChallenge(static_cast<uint256>(hu));
        uint256 uInv = invM(u);
        if (!uInv)
            return std::nullopt;
        last = u;
        if (!ipaFoldStep(a, b, Gw, Hw, half, u, uInv))
            return std::nullopt;
        cur = half;
    }
    uint256 aFinal = a[0];
    uint256 bFinal = b[0];

    // Wire: A S T1 T2 tau_x mu t L[] R[] a b
    Buffer proof(4 * kPt + 3 * kSc + 2 * rounds * kPt + 2 * kSc);
    unsigned char* p = proof.data();
    auto putPt = [&](secp256k1_pubkey const& pk) {
        if (!serPt(pk, p))
            return false;
        p += kPt;
        return true;
    };
    if (!putPt(*A) || !putPt(*S) || !putPt(*T1) || !putPt(*T2))
        return std::nullopt;
    std::memcpy(p, tauX.data(), kSc);
    p += kSc;
    std::memcpy(p, mu.data(), kSc);
    p += kSc;
    std::memcpy(p, tHat.data(), kSc);
    p += kSc;
    for (std::size_t i = 0; i < rounds; ++i)
        if (!putPt(Lr[i]))
            return std::nullopt;
    for (std::size_t i = 0; i < rounds; ++i)
        if (!putPt(Rr[i]))
            return std::nullopt;
    std::memcpy(p, aFinal.data(), kSc);
    p += kSc;
    std::memcpy(p, bFinal.data(), kSc);
    return proof;
}

bool
bpVerify(std::vector<secp256k1_pubkey> const& V, Slice const& proof, Slice const& tr)
{
    std::size_t const m = V.size();
    if (m == 0 || m > 4)
        return false;
    std::size_t const n = kBits * m;
    std::size_t const rounds = bpRounds(n);
    std::size_t const expected = 4 * kPt + 3 * kSc + 2 * rounds * kPt + 2 * kSc;
    if (proof.size() != expected)
        return false;

    unsigned char const* p = proof.data();
    auto takePt = [&](secp256k1_pubkey& out) {
        if (!parsePt(Slice(p, kPt), out))
            return false;
        p += kPt;
        return true;
    };
    secp256k1_pubkey A, S, T1, T2;
    if (!takePt(A) || !takePt(S) || !takePt(T1) || !takePt(T2))
        return false;
    uint256 tauX, mu, tHat;
    std::memcpy(tauX.data(), p, kSc);
    p += kSc;
    std::memcpy(mu.data(), p, kSc);
    p += kSc;
    std::memcpy(tHat.data(), p, kSc);
    p += kSc;
    if (!isConfidentialScalar(tauX) || !isConfidentialScalar(mu) || !isConfidentialScalar(tHat))
        return false;
    std::vector<secp256k1_pubkey> Lr(rounds), Rr(rounds);
    for (std::size_t i = 0; i < rounds; ++i)
        if (!takePt(Lr[i]))
            return false;
    for (std::size_t i = 0; i < rounds; ++i)
        if (!takePt(Rr[i]))
            return false;
    uint256 aFinal, bFinal;
    std::memcpy(aFinal.data(), p, kSc);
    p += kSc;
    std::memcpy(bFinal.data(), p, kSc);
    if (!isConfidentialScalar(aFinal) || !isConfidentialScalar(bFinal))
        return false;

    std::vector<secp256k1_pubkey> G, Hv;
    secp256k1_pubkey U;
    if (!loadGens(n, G, Hv, U))
        return false;

    sha512_half_hasher hy;
    Hraw(hy, kBpDom, sizeof(kBpDom) - 1);
    unsigned char tmp4[4];
    be32Enc(static_cast<std::uint32_t>(n), tmp4);
    Hraw(hy, tmp4, 4);
    be32Enc(static_cast<std::uint32_t>(m), tmp4);
    Hraw(hy, tmp4, 4);
    for (auto const& vj : V)
        Hpt(hy, vj);
    Hpt(hy, A);
    Hpt(hy, S);
    Hraw(hy, tr.data(), tr.size());
    uint256 y = reduceChallenge(static_cast<uint256>(hy));

    sha512_half_hasher hz;
    Hraw(hz, kBpDom, sizeof(kBpDom) - 1);
    Hsc(hz, y);
    Hpt(hz, A);
    Hpt(hz, S);
    Hraw(hz, tr.data(), tr.size());
    uint256 z = reduceChallenge(static_cast<uint256>(hz));

    sha512_half_hasher hx;
    Hpt(hx, A);
    Hpt(hx, S);
    Hsc(hx, y);
    Hsc(hx, z);
    Hpt(hx, T1);
    Hpt(hx, T2);
    Hraw(hx, tr.data(), tr.size());
    uint256 x = reduceChallenge(static_cast<uint256>(hx));

    sha512_half_hasher hipa;
    Hpt(hipa, A);
    Hpt(hipa, S);
    Hpt(hipa, T1);
    Hpt(hipa, T2);
    Hsc(hipa, y);
    Hsc(hipa, z);
    Hsc(hipa, x);
    Hsc(hipa, tHat);
    Hraw(hipa, tr.data(), tr.size());
    uint256 ipaSeed = static_cast<uint256>(hipa);

    sha512_half_hasher hux;
    Hsc(hux, ipaSeed);
    Hsc(hux, tHat);
    uint256 ux = reduceChallenge(static_cast<uint256>(hux));

    uint256 const one{std::uint64_t{1}};
    std::vector<uint256> yPow(n);
    uint256 yp = one;
    for (std::size_t k = 0; k < n; ++k)
    {
        yPow[k] = yp;
        yp = mulM(yp, y);
    }
    std::vector<uint256> zJ2(m);
    uint256 zj = mulM(z, z);
    for (std::size_t j = 0; j < m; ++j)
    {
        zJ2[j] = zj;
        zj = mulM(zj, z);
    }
    uint256 yInv = invM(y);
    if (!yInv)
        return false;
    std::vector<secp256k1_pubkey> Hp(n);
    uint256 yInvPow = one;
    for (std::size_t k = 0; k < n; ++k)
    {
        auto hp = tmul(Hv[k], yInvPow.data());
        if (!hp)
            return false;
        Hp[k] = *hp;
        yInvPow = mulM(yInvPow, yInv);
    }

    // Build P = A + x S + sum_k (l0 coeffs)*G + ...  (standard verification equation)
    // P = A + S^x - mu*H + inner-product terms + sum z^{j+2} V_j (tau_x checked separately)
    //
    // Verify: tHat*G + tauX*H == T1^x + T2^{x^2} + sum z^{j+2} V_j  + delta(y,z)*G
    // and IPA on P.

    // delta(y,z) = (z - z^2)*<1^n, y^n> - sum_j z^{j+2}*<1^n, 2^n_j>
    uint256 sumY;
    for (std::size_t k = 0; k < n; ++k)
        sumY = addM(sumY, yPow[k]);
    uint256 z2 = mulM(z, z);
    // delta = (z - z^2)<1, y> - sum_j z^{j+3}<1, 2^n>  (aggregated Bulletproofs)
    uint256 delta = mulM(subM(z, z2), sumY);
    uint256 sum2;
    for (std::size_t i = 0; i < kBits; ++i)
        sum2 = addM(sum2, u64ToSc(1ull << i));
    uint256 zj3 = mulM(z2, z);  // z^3
    for (std::size_t j = 0; j < m; ++j)
    {
        delta = subM(delta, mulM(zj3, sum2));
        zj3 = mulM(zj3, z);
    }

    // Check T: tHat*G + tauX*H =? delta*G + T1*x + T2*x^2 + sum zJ2[j]*V[j]
    {
        auto lhs = addOpt(mkPt(tHat.data()), tmul(pedH(), tauX.data()));
        auto rhs = addOpt(
            mkPt(delta.data()), addOpt(tmul(T1, x.data()), tmul(T2, mulM(x, x).data())));
        for (std::size_t j = 0; j < m; ++j)
        {
            auto term = tmul(V[j], zJ2[j].data());
            if (!term)
                return false;
            rhs = addOpt(rhs, term);
        }
        if (!lhs || !rhs)
            return false;
        unsigned char lb[kPt], rb[kPt];
        if (!serPt(*lhs, lb) || !serPt(*rhs, rb))
            return false;
        if (std::memcmp(lb, rb, kPt) != 0)
            return false;
    }

    // Build IPA input commitment P =
    // A + x*S + sum_k (-z)*G_k + sum_k (z*y^k)*H'_k + sum_j z^{j+2} * (sum_i 2^i H'_{j*64+i}) 
    // Actually standard:
    // P = A + x*S + < -z*1 + ..., G> + <..., H'>  which equals <l,G> + <r,H'> + mu*H
    // Verifier computes P' = A + x S - mu H + sum (-z) G_i + sum (z y^i + z^{j+2} 2^i) H'_i
    // Then IPA verifies P' + tHat*(ux U)  against a,b fold.

    std::vector<uint256> gSc(n), hSc(n);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < kBits; ++i)
        {
            std::size_t const k = j * kBits + i;
            gSc[k] = negM(z);
            hSc[k] = addM(mulM(z, yPow[k]), mulM(zJ2[j], u64ToSc(1ull << i)));
        }
    }

    auto P = addOpt(std::optional<secp256k1_pubkey>(A), tmul(S, x.data()));
    {
        auto muH = tmul(pedH(), mu.data());
        if (!muH)
            return false;
        auto nmu = negPk(*muH);
        if (!nmu)
            return false;
        P = addOpt(P, nmu);
    }
    P = addOpt(P, msm(G, gSc));
    P = addOpt(P, msm(Hp, hSc));
    if (!P)
        return false;

    // Re-derive u challenges and fold P with L,R; fold generators; check final.
    std::vector<uint256> us(rounds), uInvs(rounds);
    uint256 last = ipaSeed;
    for (std::size_t i = 0; i < rounds; ++i)
    {
        sha512_half_hasher hu;
        Hsc(hu, last);
        Hpt(hu, Lr[i]);
        Hpt(hu, Rr[i]);
        us[i] = reduceChallenge(static_cast<uint256>(hu));
        uInvs[i] = invM(us[i]);
        if (!uInvs[i])
            return false;
        last = us[i];
    }

    // P_final = P + sum (u^2 L + u^{-2} R)
    auto Pcur = P;
    for (std::size_t i = 0; i < rounds; ++i)
    {
        uint256 u2 = mulM(us[i], us[i]);
        uint256 ui2 = mulM(uInvs[i], uInvs[i]);
        auto tL = tmul(Lr[i], u2.data());
        auto tR = tmul(Rr[i], ui2.data());
        if (!tL || !tR)
            return false;
        Pcur = addOpt(addOpt(Pcur, tL), tR);
        if (!Pcur)
            return false;
    }

    // Fold generators to single Gf, Hf
    std::vector<secp256k1_pubkey> Gw = G, Hw = Hp;
    std::size_t cur = n;
    for (std::size_t i = 0; i < rounds; ++i)
    {
        std::size_t half = cur / 2;
        // dummy a,b for fold of gens only
        std::vector<uint256> a(cur), b(cur);
        if (!ipaFoldStep(a, b, Gw, Hw, half, us[i], uInvs[i]))
            return false;
        cur = half;
    }

    auto rhs = addOpt(tmul(Gw[0], aFinal.data()), tmul(Hw[0], bFinal.data()));
    auto abux = mulM(mulM(aFinal, bFinal), ux);
    if (abux.isNonZero())
    {
        auto ut = tmul(U, abux.data());
        if (!ut)
            return false;
        rhs = addOpt(rhs, ut);
    }
    // Also need tHat * ux * U already in? Standard check:
    // P_final == a*Gf + b*Hf + a*b*ux*U
    // But P was built without tHat*ux*U; prover IPA uses L,R that include ux terms.
    // The commitment for IPA is P_ipa = <l,G> + <r,H'> + tHat*ux*U = (A+xS-muH+...) + tHat*ux*U
    auto tU = tmul(U, mulM(tHat, ux).data());
    if (!tU)
        return false;
    Pcur = addOpt(Pcur, tU);
    if (!Pcur || !rhs)
        return false;
    unsigned char lb[kPt], rb[kPt];
    if (!serPt(*Pcur, lb) || !serPt(*rhs, rb))
        return false;
    return std::memcmp(lb, rb, kPt) == 0;
}


uint256
clawbackChallenge(
    secp256k1_pubkey const& K1,
    secp256k1_pubkey const& K2,
    secp256k1_pubkey const& R,
    secp256k1_pubkey const& B,
    Slice const& issuerPk,
    Slice const& transcript)
{
    sha512_half_hasher h;
    Hpt(h, K1);
    Hpt(h, K2);
    Hpt(h, R);
    Hpt(h, B);
    Hraw(h, issuerPk.data(), issuerPk.size());
    Hraw(h, transcript.data(), transcript.size());
    return reduceChallenge(static_cast<uint256>(h));
}

uint256
convertBackChallenge(
    secp256k1_pubkey const& Apk,
    secp256k1_pubkey const& Adec,
    secp256k1_pubkey const& Abal,
    Slice const& holderPk,
    Slice const& spending,
    Slice const& Cb,
    Slice const& transcript)
{
    sha512_half_hasher h;
    Hpt(h, Apk);
    Hpt(h, Adec);
    Hpt(h, Abal);
    Hraw(h, holderPk.data(), holderPk.size());
    Hraw(h, spending.data(), spending.size());
    Hraw(h, Cb.data(), Cb.size());
    Hraw(h, transcript.data(), transcript.size());
    return reduceChallenge(static_cast<uint256>(h));
}

}  // namespace

std::optional<Buffer>
pedersenCommit(std::uint64_t v, uint256 const& r)
{
    auto p = pedersenPoint(v, r);
    if (!p)
        return std::nullopt;
    Buffer out(kPt);
    if (!serPt(*p, out.data()))
        return std::nullopt;
    return out;
}

Buffer
clawbackTranscript(AccountID const& issuer, AccountID const& holder, MPTID const& mptId)
{
    static constexpr char const d[] = "XLS-0096/ConfidentialMPTClawback";
    Buffer out(sizeof(d) - 1 + issuer.size() + holder.size() + mptId.size());
    auto* p = out.data();
    std::memcpy(p, d, sizeof(d) - 1);
    p += sizeof(d) - 1;
    std::memcpy(p, issuer.data(), issuer.size());
    p += issuer.size();
    std::memcpy(p, holder.data(), holder.size());
    p += holder.size();
    std::memcpy(p, mptId.data(), mptId.size());
    return out;
}

Buffer
convertBackTranscript(AccountID const& account, MPTID const& mptId, std::uint32_t version)
{
    static constexpr char const d[] = "XLS-0096/ConfidentialMPTConvertBack";
    Buffer out(sizeof(d) - 1 + account.size() + mptId.size() + 4);
    auto* p = out.data();
    std::memcpy(p, d, sizeof(d) - 1);
    p += sizeof(d) - 1;
    std::memcpy(p, account.data(), account.size());
    p += account.size();
    std::memcpy(p, mptId.data(), mptId.size());
    p += mptId.size();
    be32Enc(version, p);
    return out;
}

Buffer
sendTranscript(
    AccountID const& sender,
    AccountID const& dest,
    MPTID const& mptId,
    std::uint32_t version)
{
    static constexpr char const d[] = "XLS-0096/ConfidentialMPTSend";
    Buffer out(sizeof(d) - 1 + sender.size() + dest.size() + mptId.size() + 4);
    auto* p = out.data();
    std::memcpy(p, d, sizeof(d) - 1);
    p += sizeof(d) - 1;
    std::memcpy(p, sender.data(), sender.size());
    p += sender.size();
    std::memcpy(p, dest.data(), dest.size());
    p += dest.size();
    std::memcpy(p, mptId.data(), mptId.size());
    p += mptId.size();
    be32Enc(version, p);
    return out;
}

std::optional<Buffer>
clawbackProve(
    Slice const& issuerCt,
    Slice const& issuerPk,
    std::uint64_t m,
    Slice const& issuerSk,
    Slice const& transcript)
{
    secp256k1_pubkey R, S, pk;
    if (!parseCt(issuerCt, R, S) || !parsePt(issuerPk, pk) || issuerSk.size() != 32 ||
        secp256k1_ec_seckey_verify(secp256k1Context(), issuerSk.data()) != 1)
        return std::nullopt;
    if (m > kMaxMpTokenAmount)
        return std::nullopt;
    auto const expectedPk = mkPt(issuerSk.data());
    if (!expectedPk)
        return std::nullopt;
    unsigned char got[kPt];
    unsigned char exp[kPt];
    if (!serPt(pk, got) || !serPt(*expectedPk, exp) || std::memcmp(got, exp, kPt) != 0)
        return std::nullopt;

    // B = S - mG; relation: B = sk·R
    secp256k1_pubkey B = S;
    if (m != 0)
    {
        auto mG = mkPt(u64ToSc(m).data());
        if (!mG)
            return std::nullopt;
        auto b = psub(S, *mG);
        if (!b)
            return std::nullopt;
        B = *b;
    }

    uint256 k = randSc();
    auto K1 = mkPt(k.data());
    auto K2 = tmul(R, k.data());
    if (!K1 || !K2)
        return std::nullopt;
    uint256 c = clawbackChallenge(*K1, *K2, R, B, issuerPk, transcript);
    uint256 sk;
    std::memcpy(sk.data(), issuerSk.data(), 32);
    uint256 s = resp(k, c, sk);

    Buffer proof(kConfidentialClawbackProofLength);
    std::memcpy(proof.data(), c.data(), kSc);
    std::memcpy(proof.data() + kSc, s.data(), kSc);
    return proof;
}

bool
clawbackVerify(
    Slice const& issuerCt,
    Slice const& issuerPk,
    std::uint64_t m,
    Slice const& proof,
    Slice const& transcript)
{
    if (proof.size() != kConfidentialClawbackProofLength || m > kMaxMpTokenAmount)
        return false;
    secp256k1_pubkey R, S, pk;
    if (!parseCt(issuerCt, R, S) || !parsePt(issuerPk, pk))
        return false;
    uint256 c, s;
    std::memcpy(c.data(), proof.data(), kSc);
    std::memcpy(s.data(), proof.data() + kSc, kSc);
    if (!isConfidentialScalar(c) || !isConfidentialScalar(s))
        return false;

    secp256k1_pubkey B = S;
    if (m != 0)
    {
        auto mG = mkPt(u64ToSc(m).data());
        if (!mG)
            return false;
        auto b = psub(S, *mG);
        if (!b)
            return false;
        B = *b;
    }

    auto sG = mkPt(s.data());
    auto cPk = tmul(pk, c.data());
    if (!sG || !cPk)
        return false;
    auto nCPk = negPk(*cPk);
    if (!nCPk)
        return false;
    auto K1 = comb(*sG, *nCPk);
    if (!K1)
        return false;

    auto sR = tmul(R, s.data());
    auto cB = tmul(B, c.data());
    if (!sR || !cB)
        return false;
    auto nCB = negPk(*cB);
    if (!nCB)
        return false;
    auto K2 = comb(*sR, *nCB);
    if (!K2)
        return false;

    return c == clawbackChallenge(*K1, *K2, R, B, issuerPk, transcript);
}

static std::optional<Buffer>
convertBackSigmaProve(
    Slice const& holderPk,
    uint256 const& sk,
    Slice const& spendingCt,
    secp256k1_pubkey const& Cb,
    std::uint64_t balance,
    uint256 const& gamma,
    Slice const& transcript)
{
    secp256k1_pubkey pk, R, S;
    if (!parsePt(holderPk, pk) || !parseCt(spendingCt, R, S))
        return std::nullopt;

    uint256 kSk = randSc();
    uint256 kB = randSc();
    uint256 kG = randSc();

    auto Apk = mkPt(kSk.data());
    auto kbG = mkPt(kB.data());
    auto kskR = tmul(R, kSk.data());
    if (!Apk || !kbG || !kskR)
        return std::nullopt;
    auto Adec = comb(*kbG, *kskR);
    auto kgH = tmul(pedH(), kG.data());
    if (!Adec || !kgH)
        return std::nullopt;
    auto Abal = comb(*kbG, *kgH);
    if (!Abal)
        return std::nullopt;

    unsigned char cbBytes[kPt];
    if (!serPt(Cb, cbBytes))
        return std::nullopt;

    uint256 c = convertBackChallenge(
        *Apk, *Adec, *Abal, holderPk, spendingCt, Slice(cbBytes, kPt), transcript);

    Buffer proof(kConfidentialConvertBackSigmaLength);
    std::memcpy(proof.data(), c.data(), 32);
    std::memcpy(proof.data() + 32, resp(kSk, c, sk).data(), 32);
    std::memcpy(proof.data() + 64, resp(kB, c, u64ToSc(balance)).data(), 32);
    std::memcpy(proof.data() + 96, resp(kG, c, gamma).data(), 32);
    return proof;
}

static bool
convertBackSigmaVerify(
    Slice const& holderPk,
    Slice const& spendingCt,
    Slice const& balanceCommitment,
    Slice const& sigma,
    Slice const& transcript)
{
    if (sigma.size() != kConfidentialConvertBackSigmaLength)
        return false;
    secp256k1_pubkey pk, R, S, Cb;
    if (!parsePt(holderPk, pk) || !parseCt(spendingCt, R, S) || !parsePt(balanceCommitment, Cb))
        return false;
    uint256 c, sSk, sB, sG;
    std::memcpy(c.data(), sigma.data(), 32);
    std::memcpy(sSk.data(), sigma.data() + 32, 32);
    std::memcpy(sB.data(), sigma.data() + 64, 32);
    std::memcpy(sG.data(), sigma.data() + 96, 32);
    if (!isConfidentialScalar(c) || !isConfidentialScalar(sSk) || !isConfidentialScalar(sB) ||
        !isConfidentialScalar(sG))
        return false;

    auto sSkG = mkPt(sSk.data());
    auto cPk = tmul(pk, c.data());
    if (!sSkG || !cPk)
        return false;
    auto Apk = psub(*sSkG, *cPk);
    if (!Apk)
        return false;

    auto sBG = mkPt(sB.data());
    auto sSkR = tmul(R, sSk.data());
    auto cS = tmul(S, c.data());
    if (!sBG || !sSkR || !cS)
        return false;
    auto tmp = comb(*sBG, *sSkR);
    if (!tmp)
        return false;
    auto Adec = psub(*tmp, *cS);
    if (!Adec)
        return false;

    auto sGH = tmul(pedH(), sG.data());
    auto cCb = tmul(Cb, c.data());
    if (!sGH || !cCb)
        return false;
    tmp = comb(*sBG, *sGH);
    if (!tmp)
        return false;
    auto Abal = psub(*tmp, *cCb);
    if (!Abal)
        return false;

    return c == convertBackChallenge(
               *Apk, *Adec, *Abal, holderPk, spendingCt, balanceCommitment, transcript);
}

static uint256
sendChallenge(std::vector<secp256k1_pubkey> const& pts, Slice const& transcript)
{
    sha512_half_hasher h;
    for (auto const& p : pts)
        Hpt(h, p);
    Hraw(h, transcript.data(), transcript.size());
    return reduceChallenge(static_cast<uint256>(h));
}

static std::optional<Buffer>
sendSigmaProve(
    Slice const& senderPk,
    uint256 const& sk,
    std::vector<secp256k1_pubkey> const& Pks,
    std::vector<secp256k1_pubkey> const& C2,
    secp256k1_pubkey const& C1,
    secp256k1_pubkey const& Cm,
    secp256k1_pubkey const& Cb,
    secp256k1_pubkey const& B1,
    secp256k1_pubkey const& B2,
    std::uint64_t amount,
    std::uint64_t balance,
    uint256 const& r,
    uint256 const& gamma,
    Slice const& transcript)
{
    std::size_t const n = Pks.size();
    uint256 kr = randSc();
    uint256 km = randSc();
    uint256 kb = randSc();
    uint256 ksk = randSc();
    uint256 kg = randSc();

    auto T1 = mkPt(kr.data());
    if (!T1)
        return std::nullopt;
    std::vector<secp256k1_pubkey> T2(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        auto mG = mkPt(km.data());
        auto rP = tmul(Pks[i], kr.data());
        if (!mG || !rP)
            return std::nullopt;
        auto t = comb(*mG, *rP);
        if (!t)
            return std::nullopt;
        T2[i] = *t;
    }
    auto TmG = mkPt(km.data());
    auto TrH = tmul(pedH(), kr.data());
    if (!TmG || !TrH)
        return std::nullopt;
    auto Tm = comb(*TmG, *TrH);
    auto Tsk1 = mkPt(ksk.data());
    auto TbG = mkPt(kb.data());
    auto TskB = tmul(B1, ksk.data());
    auto TgH = tmul(pedH(), kg.data());
    if (!Tm || !Tsk1 || !TbG || !TskB || !TgH)
        return std::nullopt;
    auto Tsk2 = comb(*TbG, *TskB);
    auto Tb = comb(*TbG, *TgH);
    if (!Tsk2 || !Tb)
        return std::nullopt;

    secp256k1_pubkey pkA;
    if (!parsePt(senderPk, pkA))
        return std::nullopt;

    std::vector<secp256k1_pubkey> feed;
    feed.reserve(20 + 2 * n);
    for (auto const& p : Pks)
        feed.push_back(p);
    feed.push_back(pkA);
    feed.push_back(C1);
    for (auto const& s : C2)
        feed.push_back(s);
    feed.push_back(Cm);
    feed.push_back(Cb);
    feed.push_back(B1);
    feed.push_back(B2);
    feed.push_back(*T1);
    for (auto const& t : T2)
        feed.push_back(t);
    feed.push_back(*Tm);
    feed.push_back(*Tb);
    feed.push_back(*Tsk1);
    feed.push_back(*Tsk2);

    uint256 c = sendChallenge(feed, transcript);

    Buffer proof(kConfidentialSendSigmaLength);
    std::memcpy(proof.data(), c.data(), 32);
    std::memcpy(proof.data() + 32, resp(kr, c, r).data(), 32);
    std::memcpy(proof.data() + 64, resp(km, c, u64ToSc(amount)).data(), 32);
    std::memcpy(proof.data() + 96, resp(kb, c, u64ToSc(balance)).data(), 32);
    std::memcpy(proof.data() + 128, resp(ksk, c, sk).data(), 32);
    std::memcpy(proof.data() + 160, resp(kg, c, gamma).data(), 32);
    return proof;
}

static bool
sendSigmaVerify(
    Slice const& senderPk,
    std::vector<secp256k1_pubkey> const& Pks,
    std::vector<secp256k1_pubkey> const& C2,
    secp256k1_pubkey const& C1,
    secp256k1_pubkey const& Cm,
    secp256k1_pubkey const& Cb,
    secp256k1_pubkey const& B1,
    secp256k1_pubkey const& B2,
    Slice const& sigma,
    Slice const& transcript)
{
    if (sigma.size() != kConfidentialSendSigmaLength || Pks.size() != C2.size() || Pks.empty())
        return false;
    uint256 c, sr, sm, sb, ssk, sg;
    std::memcpy(c.data(), sigma.data(), 32);
    std::memcpy(sr.data(), sigma.data() + 32, 32);
    std::memcpy(sm.data(), sigma.data() + 64, 32);
    std::memcpy(sb.data(), sigma.data() + 96, 32);
    std::memcpy(ssk.data(), sigma.data() + 128, 32);
    std::memcpy(sg.data(), sigma.data() + 160, 32);
    if (!isConfidentialScalar(c) || !isConfidentialScalar(sr) || !isConfidentialScalar(sm) ||
        !isConfidentialScalar(sb) || !isConfidentialScalar(ssk) || !isConfidentialScalar(sg))
        return false;

    secp256k1_pubkey pkA;
    if (!parsePt(senderPk, pkA))
        return false;

    auto sG = mkPt(sr.data());
    auto cC1 = tmul(C1, c.data());
    if (!sG || !cC1)
        return false;
    auto T1 = psub(*sG, *cC1);
    if (!T1)
        return false;

    std::size_t const n = Pks.size();
    std::vector<secp256k1_pubkey> T2(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        auto smG = mkPt(sm.data());
        auto srP = tmul(Pks[i], sr.data());
        auto cC2 = tmul(C2[i], c.data());
        if (!smG || !srP || !cC2)
            return false;
        auto tmp = comb(*smG, *srP);
        if (!tmp)
            return false;
        auto t = psub(*tmp, *cC2);
        if (!t)
            return false;
        T2[i] = *t;
    }

    auto smG = mkPt(sm.data());
    auto srH = tmul(pedH(), sr.data());
    auto cCm = tmul(Cm, c.data());
    if (!smG || !srH || !cCm)
        return false;
    auto tmp = comb(*smG, *srH);
    if (!tmp)
        return false;
    auto Tm = psub(*tmp, *cCm);
    if (!Tm)
        return false;

    auto sbG = mkPt(sb.data());
    auto sgH = tmul(pedH(), sg.data());
    auto cCb = tmul(Cb, c.data());
    if (!sbG || !sgH || !cCb)
        return false;
    tmp = comb(*sbG, *sgH);
    if (!tmp)
        return false;
    auto Tb = psub(*tmp, *cCb);
    if (!Tb)
        return false;

    auto sskG = mkPt(ssk.data());
    auto cPk = tmul(pkA, c.data());
    if (!sskG || !cPk)
        return false;
    auto Tsk1 = psub(*sskG, *cPk);
    if (!Tsk1)
        return false;

    auto sskB = tmul(B1, ssk.data());
    auto cB2 = tmul(B2, c.data());
    if (!sskB || !cB2)
        return false;
    tmp = comb(*sbG, *sskB);
    if (!tmp)
        return false;
    auto Tsk2 = psub(*tmp, *cB2);
    if (!Tsk2)
        return false;

    std::vector<secp256k1_pubkey> feed;
    feed.reserve(20 + 2 * n);
    for (auto const& p : Pks)
        feed.push_back(p);
    feed.push_back(pkA);
    feed.push_back(C1);
    for (auto const& s : C2)
        feed.push_back(s);
    feed.push_back(Cm);
    feed.push_back(Cb);
    feed.push_back(B1);
    feed.push_back(B2);
    feed.push_back(*T1);
    for (auto const& t : T2)
        feed.push_back(t);
    feed.push_back(*Tm);
    feed.push_back(*Tb);
    feed.push_back(*Tsk1);
    feed.push_back(*Tsk2);
    return c == sendChallenge(feed, transcript);
}

std::optional<ConvertBackProof>
convertBackProve(
    Slice const& holderPk,
    Slice const& holderSk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    std::uint64_t balance,
    uint256 const& r,
    uint256 const& gamma,
    Slice const& transcript)
{
    if (amount > balance || balance > kMaxMpTokenAmount || amount > kMaxMpTokenAmount)
        return std::nullopt;
    if (holderSk.size() != 32)
        return std::nullopt;
    uint256 sk;
    std::memcpy(sk.data(), holderSk.data(), 32);
    if (!isConfidentialScalar(sk) || !isConfidentialScalar(r) || !isConfidentialScalar(gamma))
        return std::nullopt;

    auto holderEnc = elgamalEncrypt(holderPk, amount, r);
    auto issuerEnc = elgamalEncrypt(issuerPk, amount, r);
    if (!holderEnc || !issuerEnc)
        return std::nullopt;
    Buffer auditorEnc;
    if (auditorPk)
    {
        auto ae = elgamalEncrypt(*auditorPk, amount, r);
        if (!ae)
            return std::nullopt;
        auditorEnc = std::move(*ae);
    }

    auto Cb = pedersenPoint(balance, gamma);
    if (!Cb)
        return std::nullopt;
    Buffer balanceCommitment(kPt);
    if (!serPt(*Cb, balanceCommitment.data()))
        return std::nullopt;

    auto sigma = convertBackSigmaProve(holderPk, sk, spendingCt, *Cb, balance, gamma, transcript);
    if (!sigma)
        return std::nullopt;

    std::uint64_t const remain = balance - amount;
    uint256 blindRemain = subM(gamma, r);
    if (!isConfidentialScalar(blindRemain))
        return std::nullopt;
    auto bp = bpProve({remain}, {blindRemain}, transcript);
    if (!bp || bp->size() != kConfidentialSingleBulletproofLength)
        return std::nullopt;

    ConvertBackProof out;
    out.holderEnc = std::move(*holderEnc);
    out.issuerEnc = std::move(*issuerEnc);
    out.auditorEnc = std::move(auditorEnc);
    out.balanceCommitment = std::move(balanceCommitment);
    out.zkProof = Buffer(kConfidentialConvertBackZkLength);
    std::memcpy(out.zkProof.data(), sigma->data(), sigma->size());
    std::memcpy(out.zkProof.data() + sigma->size(), bp->data(), bp->size());
    return out;
}

bool
convertBackVerify(
    Slice const& holderPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    Slice const& holderEnc,
    Slice const& issuerEnc,
    std::optional<Slice> const& auditorEnc,
    uint256 const& r,
    Slice const& balanceCommitment,
    Slice const& zkProof,
    Slice const& transcript)
{
    if (zkProof.size() != kConfidentialConvertBackZkLength || amount > kMaxMpTokenAmount)
        return false;
    if (auditorPk.has_value() != auditorEnc.has_value())
        return false;
    if (!elgamalMatches(holderEnc, holderPk, amount, r) ||
        !elgamalMatches(issuerEnc, issuerPk, amount, r))
        return false;
    if (auditorPk && !elgamalMatches(*auditorEnc, *auditorPk, amount, r))
        return false;

    Slice const sigma(zkProof.data(), kConfidentialConvertBackSigmaLength);
    Slice const bp(
        zkProof.data() + kConfidentialConvertBackSigmaLength, kConfidentialSingleBulletproofLength);
    if (!convertBackSigmaVerify(holderPk, spendingCt, balanceCommitment, sigma, transcript))
        return false;

    secp256k1_pubkey Cb;
    if (!parsePt(balanceCommitment, Cb))
        return false;
    auto Camt = pedersenPoint(amount, r);
    if (!Camt)
        return false;
    auto Crem = psub(Cb, *Camt);
    if (!Crem)
        return false;
    return bpVerify({*Crem}, bp, transcript);
}

std::optional<SendProof>
sendProve(
    Slice const& senderPk,
    Slice const& senderSk,
    Slice const& destPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    std::uint64_t amount,
    std::uint64_t balance,
    uint256 const& r,
    uint256 const& gamma,
    Slice const& transcript)
{
    if (amount > balance || balance > kMaxMpTokenAmount || amount > kMaxMpTokenAmount)
        return std::nullopt;
    if (senderSk.size() != 32)
        return std::nullopt;
    uint256 sk;
    std::memcpy(sk.data(), senderSk.data(), 32);
    if (!isConfidentialScalar(sk) || !isConfidentialScalar(r) || !isConfidentialScalar(gamma))
        return std::nullopt;

    auto senderEnc = elgamalEncrypt(senderPk, amount, r);
    auto destEnc = elgamalEncrypt(destPk, amount, r);
    auto issuerEnc = elgamalEncrypt(issuerPk, amount, r);
    if (!senderEnc || !destEnc || !issuerEnc)
        return std::nullopt;
    Buffer auditorEnc;
    if (auditorPk)
    {
        auto ae = elgamalEncrypt(*auditorPk, amount, r);
        if (!ae)
            return std::nullopt;
        auditorEnc = std::move(*ae);
    }

    auto Cm = pedersenPoint(amount, r);
    auto Cb = pedersenPoint(balance, gamma);
    if (!Cm || !Cb)
        return std::nullopt;
    Buffer amountCommitment(kPt);
    Buffer balanceCommitment(kPt);
    if (!serPt(*Cm, amountCommitment.data()) || !serPt(*Cb, balanceCommitment.data()))
        return std::nullopt;

    std::vector<secp256k1_pubkey> Pks;
    std::vector<secp256k1_pubkey> C2;
    secp256k1_pubkey C1{};
    auto addCt = [&](Slice const& pk, Slice const& ct) -> bool {
        secp256k1_pubkey Ri, Si, P;
        if (!parseCt(ct, Ri, Si) || !parsePt(pk, P))
            return false;
        if (Pks.empty())
            C1 = Ri;
        else
        {
            unsigned char a[kPt], b[kPt];
            if (!serPt(C1, a) || !serPt(Ri, b) || std::memcmp(a, b, kPt) != 0)
                return false;
        }
        Pks.push_back(P);
        C2.push_back(Si);
        return true;
    };
    if (!addCt(senderPk, *senderEnc) || !addCt(destPk, *destEnc) || !addCt(issuerPk, *issuerEnc))
        return std::nullopt;
    if (auditorPk && !addCt(*auditorPk, auditorEnc))
        return std::nullopt;

    secp256k1_pubkey B1, B2;
    if (!parseCt(spendingCt, B1, B2))
        return std::nullopt;

    auto sigma = sendSigmaProve(
        senderPk, sk, Pks, C2, C1, *Cm, *Cb, B1, B2, amount, balance, r, gamma, transcript);
    if (!sigma)
        return std::nullopt;

    std::uint64_t const remain = balance - amount;
    uint256 blindRemain = subM(gamma, r);
    if (!isConfidentialScalar(blindRemain))
        return std::nullopt;
    auto bp = bpProve({amount, remain}, {r, blindRemain}, transcript);
    if (!bp || bp->size() != kConfidentialAggregatedBulletproofLength)
        return std::nullopt;

    SendProof out;
    out.senderEnc = std::move(*senderEnc);
    out.destEnc = std::move(*destEnc);
    out.issuerEnc = std::move(*issuerEnc);
    out.auditorEnc = std::move(auditorEnc);
    out.amountCommitment = std::move(amountCommitment);
    out.balanceCommitment = std::move(balanceCommitment);
    out.zkProof = Buffer(kConfidentialSendZkLength);
    std::memcpy(out.zkProof.data(), sigma->data(), sigma->size());
    std::memcpy(out.zkProof.data() + sigma->size(), bp->data(), bp->size());
    return out;
}

bool
sendVerify(
    Slice const& senderPk,
    Slice const& destPk,
    Slice const& issuerPk,
    std::optional<Slice> const& auditorPk,
    Slice const& spendingCt,
    Slice const& senderEnc,
    Slice const& destEnc,
    Slice const& issuerEnc,
    std::optional<Slice> const& auditorEnc,
    Slice const& amountCommitment,
    Slice const& balanceCommitment,
    Slice const& zkProof,
    Slice const& transcript)
{
    if (zkProof.size() != kConfidentialSendZkLength)
        return false;
    if (auditorPk.has_value() != auditorEnc.has_value())
        return false;

    std::vector<secp256k1_pubkey> Pks;
    std::vector<secp256k1_pubkey> C2;
    secp256k1_pubkey C1{};
    auto addCt = [&](Slice const& pk, Slice const& ct) -> bool {
        secp256k1_pubkey Ri, Si, P;
        if (!parseCt(ct, Ri, Si) || !parsePt(pk, P))
            return false;
        if (Pks.empty())
            C1 = Ri;
        else
        {
            unsigned char a[kPt], b[kPt];
            if (!serPt(C1, a) || !serPt(Ri, b) || std::memcmp(a, b, kPt) != 0)
                return false;
        }
        Pks.push_back(P);
        C2.push_back(Si);
        return true;
    };
    if (!addCt(senderPk, senderEnc) || !addCt(destPk, destEnc) || !addCt(issuerPk, issuerEnc))
        return false;
    if (auditorPk && (!auditorEnc || !addCt(*auditorPk, *auditorEnc)))
        return false;

    secp256k1_pubkey Cm, Cb, B1, B2;
    if (!parsePt(amountCommitment, Cm) || !parsePt(balanceCommitment, Cb) ||
        !parseCt(spendingCt, B1, B2))
        return false;

    Slice const sigma(zkProof.data(), kConfidentialSendSigmaLength);
    Slice const bp(
        zkProof.data() + kConfidentialSendSigmaLength,
        kConfidentialAggregatedBulletproofLength);
    if (!sendSigmaVerify(senderPk, Pks, C2, C1, Cm, Cb, B1, B2, sigma, transcript))
        return false;

    auto Crem = psub(Cb, Cm);
    if (!Crem)
        return false;
    return bpVerify({Cm, *Crem}, bp, transcript);
}

}  // namespace xrpl
