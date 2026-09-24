#include <xrpl/protocol/Bulletproof.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace xrpl::confidential {

namespace {

using Scalars = std::vector<Scalar>;
using Points = std::vector<Point>;

// Section 4.4: each challenge hashes the whole transcript so far, starting
// with the statement, and is appended once drawn.
class Transcript
{
    std::vector<std::uint8_t> data_;
    bool valid_ = true;

public:
    Transcript(uint256 const& contextID, std::span<Point const> commitments)
    {
        std::string_view constexpr tag = "CMPT_BULLETPROOF";
        data_.assign(tag.begin(), tag.end());
        data_.push_back(static_cast<std::uint8_t>(commitments.size()));
        data_.insert(data_.end(), contextID.begin(), contextID.end());
        for (auto const& v : commitments)
            append(v);
    }

    void
    append(Point const& p)
    {
        auto const b = p.bytes();
        if (!b)
        {
            valid_ = false;
            return;
        }
        data_.insert(data_.end(), b->begin(), b->end());
    }

    void
    append(Scalar const& s)
    {
        data_.insert(data_.end(), s.bytes().begin(), s.bytes().end());
    }

    // A non-zero challenge, or nullopt if the transcript held an identity
    // point or the digest reduced to zero (challenges are drawn from Z_p^*).
    std::optional<Scalar>
    challenge()
    {
        if (!valid_)
            return std::nullopt;
        auto const c = Scalar::fromDigest(sha256({makeSlice(data_)}));
        if (c.isZero())
            return std::nullopt;  // LCOV_EXCL_LINE
        append(c);
        return c;
    }
};

Scalars
powers(Scalar const& x, std::size_t count)
{
    Scalars out;
    out.reserve(count);
    Scalar p = Scalar::fromUint64(1);
    for (std::size_t i = 0; i < count; ++i)
    {
        out.push_back(p);
        p = p * x;
    }
    return out;
}

Scalar
inner(std::span<Scalar const> a, std::span<Scalar const> b)
{
    Scalar sum;
    for (std::size_t i = 0; i < a.size(); ++i)
        sum = sum + a[i] * b[i];
    return sum;
}

std::size_t
log2(std::size_t n)
{
    std::size_t k = 0;
    while ((std::size_t{1} << k) < n)
        ++k;
    return k;
}

// Σ_i (z^(2+j) · 2^(i mod 64)) over bit i of value j, the r(X) offset of (71).
Scalar
bitWeight(Scalars const& zPowers, Scalars const& twoPowers, std::size_t i)
{
    return zPowers[2 + i / kRangeProofBits] * twoPowers[i % kRangeProofBits];
}

class Writer
{
    Buffer out_;
    std::size_t offset_ = 0;

public:
    explicit Writer(std::size_t size) : out_(size)
    {
    }

    void
    put(Point const& p)
    {
        auto const b = p.bytes();
        std::memcpy(out_.data() + offset_, b->data(), b->size());
        offset_ += b->size();
    }

    void
    put(Scalar const& s)
    {
        std::memcpy(out_.data() + offset_, s.bytes().data(), kScalarLength);
        offset_ += kScalarLength;
    }

    Buffer
    finish()
    {
        return std::move(out_);
    }
};

class Reader
{
    Slice in_;
    bool ok_ = true;

public:
    explicit Reader(Slice in) : in_(in)
    {
    }

    Point
    point()
    {
        if (!ok_ || in_.size() < kEcPointLength)
        {
            ok_ = false;  // LCOV_EXCL_LINE
            return {};    // LCOV_EXCL_LINE
        }
        auto p = Point::fromBytes(Slice(in_.data(), kEcPointLength));
        in_ += kEcPointLength;
        if (!p)
            ok_ = false;
        return p.value_or(Point{});
    }

    Scalar
    scalar()
    {
        if (!ok_ || in_.size() < kScalarLength)
        {
            ok_ = false;  // LCOV_EXCL_LINE
            return {};    // LCOV_EXCL_LINE
        }
        auto s = Scalar::fromBytes(Slice(in_.data(), kScalarLength));
        in_ += kScalarLength;
        if (!s)
            ok_ = false;
        return s.value_or(Scalar{});
    }

    [[nodiscard]] bool
    ok() const
    {
        return ok_ && in_.empty();
    }
};

struct Proof
{
    Point a, s, t1, t2;
    Scalar taux, mu, that;
    Points l, r;
    Scalar ipA, ipB;
};

// Honest provers hit an invalid transcript with probability about 2^-250.
constexpr int kMaxProverAttempts = 8;

std::optional<Buffer>
tryProve(
    std::span<std::uint64_t const> values,
    std::span<Scalar const> blindings,
    Points const& commitments,
    uint256 const& contextID)
{
    std::size_t const m = values.size();
    std::size_t const n = kRangeProofBits * m;
    std::size_t const k = log2(n);
    auto const gs = bulletproofGeneratorsG().subspan(0, n);
    auto const hs = bulletproofGeneratorsH().subspan(0, n);
    auto const& h = pedersenGenerator();
    auto const one = Scalar::fromUint64(1);

    Transcript transcript(contextID, commitments);

    // (41)-(47): commit to the bits a_L, a_R = a_L - 1 and blinding vectors.
    Scalars aL(n);
    Scalars aR(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        bool const bit = ((values[i / kRangeProofBits] >> (i % kRangeProofBits)) & 1) != 0;
        aL[i] = bit ? one : Scalar{};
        aR[i] = aL[i] - one;
    }
    Scalars sL(n);
    Scalars sR(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        sL[i] = Scalar::random();
        sR[i] = Scalar::random();
    }
    auto const alpha = Scalar::random();
    auto const rho = Scalar::random();

    auto commit = [&](Scalar const& blind, Scalars const& left, Scalars const& right) {
        Scalars sc{blind};
        Points pt{h};
        sc.insert(sc.end(), left.begin(), left.end());
        pt.insert(pt.end(), gs.begin(), gs.end());
        sc.insert(sc.end(), right.begin(), right.end());
        pt.insert(pt.end(), hs.begin(), hs.end());
        return multiScalarMul(sc, pt);
    };
    auto const bigA = commit(alpha, aL, aR);
    auto const bigS = commit(rho, sL, sR);
    transcript.append(bigA);
    transcript.append(bigS);
    auto const y = transcript.challenge();
    auto const z = transcript.challenge();
    if (!y || !z)
        return std::nullopt;  // LCOV_EXCL_LINE

    // l(X), r(X) and t(X) of (70)-(71).
    auto const yPowers = powers(*y, n);
    auto const zPowers = powers(*z, m + 3);
    auto const twoPowers = powers(Scalar::fromUint64(2), kRangeProofBits);
    Scalars l0(n);
    Scalars r0(n);
    Scalars r1(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        l0[i] = aL[i] - *z;
        r0[i] = yPowers[i] * (aR[i] + *z) + bitWeight(zPowers, twoPowers, i);
        r1[i] = yPowers[i] * sR[i];
    }
    auto const t1 = inner(l0, r1) + inner(sL, r0);
    auto const t2 = inner(sL, r1);

    // (52)-(56)
    auto const tau1 = Scalar::random();
    auto const tau2 = Scalar::random();
    auto const bigT1 = pedersenCommit(t1, tau1);
    auto const bigT2 = pedersenCommit(t2, tau2);
    transcript.append(bigT1);
    transcript.append(bigT2);
    auto const x = transcript.challenge();
    if (!x)
        return std::nullopt;  // LCOV_EXCL_LINE

    // (58)-(62), with tau_x adjusted for m commitments.
    Scalars l(n);
    Scalars r(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        l[i] = l0[i] + *x * sL[i];
        r[i] = r0[i] + *x * r1[i];
    }
    auto const that = inner(l, r);
    auto taux = tau2 * *x * *x + tau1 * *x;
    for (std::size_t j = 0; j < m; ++j)
        taux = taux + zPowers[2 + j] * blindings[j];
    auto const mu = alpha + rho * *x;
    transcript.append(taux);
    transcript.append(mu);
    transcript.append(that);

    // Protocol 1: fold t_hat into the inner-product argument with u^x.
    auto const xip = transcript.challenge();
    if (!xip)
        return std::nullopt;  // LCOV_EXCL_LINE
    auto const u = *xip * innerProductGenerator();

    // Protocol 2 on (g, h' = h^(y^-n), u^x): h'_i = y^-i · H_i.
    Points g(gs.begin(), gs.end());
    Points hPrime(n);
    auto const yInv = y->inverse();
    auto yInvPower = one;
    for (std::size_t i = 0; i < n; ++i)
    {
        hPrime[i] = yInvPower * hs[i];
        yInvPower = yInvPower * yInv;
    }
    Scalars a = l;
    Scalars b = r;
    Points ls;
    Points rs;
    for (std::size_t len = n; len > 1; len /= 2)
    {
        std::size_t const half = len / 2;
        auto const lo = [&](auto const& v) { return std::span(v).subspan(0, half); };
        auto const hi = [&](auto const& v) { return std::span(v).subspan(half, half); };

        // (21)-(24)
        auto const cL = inner(lo(a), hi(b));
        auto const cR = inner(hi(a), lo(b));
        auto side = [&](std::span<Scalar const> av,
                        std::span<Point const> gv,
                        std::span<Scalar const> bv,
                        std::span<Point const> hv,
                        Scalar const& c) {
            Scalars sc(av.begin(), av.end());
            Points pt(gv.begin(), gv.end());
            sc.insert(sc.end(), bv.begin(), bv.end());
            pt.insert(pt.end(), hv.begin(), hv.end());
            sc.push_back(c);
            pt.push_back(u);
            return multiScalarMul(sc, pt);
        };
        auto const bigL = side(lo(a), hi(g), hi(b), lo(hPrime), cL);
        auto const bigR = side(hi(a), lo(g), lo(b), hi(hPrime), cR);
        transcript.append(bigL);
        transcript.append(bigR);
        auto const uj = transcript.challenge();
        if (!uj)
            return std::nullopt;  // LCOV_EXCL_LINE
        auto const ujInv = uj->inverse();
        ls.push_back(bigL);
        rs.push_back(bigR);

        // (29)-(34)
        Points g2(half);
        Points h2(half);
        Scalars a2(half);
        Scalars b2(half);
        for (std::size_t i = 0; i < half; ++i)
        {
            g2[i] = ujInv * g[i] + *uj * g[half + i];
            h2[i] = *uj * hPrime[i] + ujInv * hPrime[half + i];
            a2[i] = *uj * a[i] + ujInv * a[half + i];
            b2[i] = ujInv * b[i] + *uj * b[half + i];
        }
        g = std::move(g2);
        hPrime = std::move(h2);
        a = std::move(a2);
        b = std::move(b2);
    }

    for (auto const* p : {&bigA, &bigS, &bigT1, &bigT2})
    {
        if (p->isInfinity())
            return std::nullopt;  // LCOV_EXCL_LINE
    }
    for (std::size_t j = 0; j < k; ++j)
    {
        if (ls[j].isInfinity() || rs[j].isInfinity())
            return std::nullopt;  // LCOV_EXCL_LINE
    }

    Writer w(rangeProofLength(m));
    w.put(bigA);
    w.put(bigS);
    w.put(bigT1);
    w.put(bigT2);
    w.put(taux);
    w.put(mu);
    w.put(that);
    for (std::size_t j = 0; j < k; ++j)
    {
        w.put(ls[j]);
        w.put(rs[j]);
    }
    w.put(a[0]);
    w.put(b[0]);
    return w.finish();
}

}  // namespace

Buffer
proveRange(
    std::span<std::uint64_t const> values,
    std::span<Scalar const> blindings,
    uint256 const& contextID)
{
    std::size_t const m = values.size();
    if (m == 0 || m > kMaxRangeProofValues || blindings.size() != m)
        Throw<std::invalid_argument>("confidential: unsupported range proof size");

    Points commitments;
    for (std::size_t j = 0; j < m; ++j)
    {
        commitments.push_back(pedersenCommit(Scalar::fromUint64(values[j]), blindings[j]));
        if (commitments.back().isInfinity())
            Throw<std::invalid_argument>("confidential: commitment is the identity");
    }

    for (int attempt = 0; attempt < kMaxProverAttempts; ++attempt)
    {
        if (auto proof = tryProve(values, blindings, commitments, contextID))
            return std::move(*proof);
    }
    Throw<std::runtime_error>("confidential: range prover failed");  // LCOV_EXCL_LINE
}

bool
verifyRange(std::span<Point const> commitments, Slice proof, uint256 const& contextID)
{
    std::size_t const m = commitments.size();
    if (m == 0 || m > kMaxRangeProofValues || proof.size() != rangeProofLength(m))
        return false;
    std::size_t const n = kRangeProofBits * m;
    std::size_t const k = log2(n);

    Proof p;
    Reader in(proof);
    p.a = in.point();
    p.s = in.point();
    p.t1 = in.point();
    p.t2 = in.point();
    p.taux = in.scalar();
    p.mu = in.scalar();
    p.that = in.scalar();
    for (std::size_t j = 0; j < k; ++j)
    {
        p.l.push_back(in.point());
        p.r.push_back(in.point());
    }
    p.ipA = in.scalar();
    p.ipB = in.scalar();
    if (!in.ok())
        return false;

    Transcript transcript(contextID, commitments);
    transcript.append(p.a);
    transcript.append(p.s);
    auto const y = transcript.challenge();
    auto const z = transcript.challenge();
    transcript.append(p.t1);
    transcript.append(p.t2);
    auto const x = transcript.challenge();
    transcript.append(p.taux);
    transcript.append(p.mu);
    transcript.append(p.that);
    auto const xip = transcript.challenge();
    Scalars u(k);
    for (std::size_t j = 0; j < k; ++j)
    {
        transcript.append(p.l[j]);
        transcript.append(p.r[j]);
        auto const uj = transcript.challenge();
        if (!uj)
            return false;
        u[j] = *uj;
    }
    // An identity commitment already failed at u[0]; otherwise only a zero
    // digest gets here.
    if (!y || !z || !x || !xip)
        return false;  // LCOV_EXCL_LINE

    auto const one = Scalar::fromUint64(1);
    auto const& g = Point::generator();
    auto const& h = pedersenGenerator();
    auto const gs = bulletproofGeneratorsG().subspan(0, n);
    auto const hs = bulletproofGeneratorsH().subspan(0, n);
    auto const yPowers = powers(*y, n);
    auto const zPowers = powers(*z, m + 3);
    auto const twoPowers = powers(Scalar::fromUint64(2), kRangeProofBits);

    // (72): t_hat·G + tau_x·H = Σ z^(2+j)·V_j + delta(y,z)·G + x·T1 + x²·T2,
    // delta(y,z) = (z - z²)·<1, y^n> - Σ z^(3+j)·<1, 2^64>.
    {
        Scalar sumY;
        for (auto const& yi : yPowers)
            sumY = sumY + yi;
        auto const sumTwo = Scalar::fromUint64(std::numeric_limits<std::uint64_t>::max());
        auto delta = (*z - zPowers[2]) * sumY;
        for (std::size_t j = 0; j < m; ++j)
            delta = delta - zPowers[3 + j] * sumTwo;

        Scalars sc{p.that - delta, p.taux, -*x, -(*x * *x)};
        Points pt{g, h, p.t1, p.t2};
        for (std::size_t j = 0; j < m; ++j)
        {
            sc.push_back(-zPowers[2 + j]);
            pt.push_back(commitments[j]);
        }
        if (!multiScalarMul(sc, pt).isInfinity())
            return false;
    }

    // Section 3.1 with P from (66): one multi-exponentiation that must
    // vanish,
    //   Σ (a·s_i + z)·G_i + Σ (y^-i·(b/s_i - z^(2+j)·2^(i mod 64)) - z)·H_i
    //   + x_ip·(a·b - t_hat)·u + mu·H - A - x·S - Σ (u_j²·L_j + u_j^-2·R_j),
    // where s_i = Π u_j^(±1) by bit (k - j) of i.
    Scalars uInv(k);
    for (std::size_t j = 0; j < k; ++j)
        uInv[j] = u[j].inverse();
    auto const yInv = y->inverse();

    Scalars sc;
    Points pt;
    sc.reserve(2 * n + 2 * k + 4);
    pt.reserve(2 * n + 2 * k + 4);
    Scalars sInv(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        Scalar si = one;
        Scalar siInv = one;
        for (std::size_t j = 0; j < k; ++j)
        {
            bool const bit = ((i >> (k - 1 - j)) & 1) != 0;
            si = si * (bit ? u[j] : uInv[j]);
            siInv = siInv * (bit ? uInv[j] : u[j]);
        }
        sInv[i] = siInv;
        sc.push_back(p.ipA * si + *z);
        pt.push_back(gs[i]);
    }
    auto yInvPower = one;
    for (std::size_t i = 0; i < n; ++i)
    {
        sc.push_back(yInvPower * (p.ipB * sInv[i] - bitWeight(zPowers, twoPowers, i)) - *z);
        pt.push_back(hs[i]);
        yInvPower = yInvPower * yInv;
    }
    sc.push_back(*xip * (p.ipA * p.ipB - p.that));
    pt.push_back(innerProductGenerator());
    sc.push_back(p.mu);
    pt.push_back(h);
    sc.push_back(-one);
    pt.push_back(p.a);
    sc.push_back(-*x);
    pt.push_back(p.s);
    for (std::size_t j = 0; j < k; ++j)
    {
        sc.push_back(-(u[j] * u[j]));
        pt.push_back(p.l[j]);
        sc.push_back(-(uInv[j] * uInv[j]));
        pt.push_back(p.r[j]);
    }
    return multiScalarMul(sc, pt).isInfinity();
}

}  // namespace xrpl::confidential
