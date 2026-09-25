#include <xrpl/protocol/ConfidentialCrypto.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/beast/utility/instrumentation.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/crypto/secure_erase.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/detail/secp256k1.h>

#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xrpl::confidential {

namespace {

// libsecp256k1 only fails these operations on inputs that the Point and
// Scalar invariants exclude. Returning the identity instead would make it
// vanish from sums, so treat a failure as a broken invariant.
// LCOV_EXCL_START
[[noreturn]] void
secp256k1Failure(char const* operation)
{
    UNREACHABLE("xrpl::confidential : unexpected libsecp256k1 failure");
    Throw<std::logic_error>(std::string("confidential: libsecp256k1 failed: ") + operation);
}
// LCOV_EXCL_STOP

// The secp256k1 group order n, big-endian.
constexpr std::array<std::uint8_t, kScalarLength> kGroupOrder{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

using ScalarBytes = std::array<std::uint8_t, kScalarLength>;

// Scalar arithmetic runs on secrets (the Bulletproof bits among them), so
// none of these helpers branches on, or indexes by, a value: conditions
// become all-ones/all-zero masks.

// 0xFF if the bytes are all zero, else 0x00.
std::uint8_t
zeroMask(ScalarBytes const& s)
{
    std::uint32_t acc = 0;
    for (auto const b : s)
        acc |= b;
    std::uint32_t const nonZero = (acc | (0u - acc)) >> 31;
    return static_cast<std::uint8_t>(nonZero - 1);
}

// dst = mask ? src : dst
void
select(ScalarBytes& dst, ScalarBytes const& src, std::uint8_t mask)
{
    for (std::size_t i = 0; i < kScalarLength; ++i)
        dst[i] = static_cast<std::uint8_t>((dst[i] & ~mask) | (src[i] & mask));
}

// out = a - b over 256 bits; returns the final borrow (0 or 1).
std::uint32_t
subtract(ScalarBytes const& a, ScalarBytes const& b, ScalarBytes& out)
{
    std::uint32_t borrow = 0;
    for (std::size_t i = kScalarLength; i-- > 0;)
    {
        std::uint32_t const diff = std::uint32_t{a[i]} - b[i] - borrow;
        out[i] = static_cast<std::uint8_t>(diff);
        borrow = diff >> 31;
    }
    return borrow;
}

// Reduces a value in [0, 2n) that is given as its low 256 bits and a carry.
void
reduceOnce(ScalarBytes& value, std::uint32_t carry)
{
    ScalarBytes reduced;
    std::uint32_t const borrow = subtract(value, kGroupOrder, reduced);
    select(value, reduced, static_cast<std::uint8_t>(0u - (carry | (borrow ^ 1))));
    secureErase(reduced.data(), reduced.size());
}

Slice
asSlice(std::string_view s)
{
    return Slice(s.data(), s.size());
}

void
appendU32(std::vector<std::uint8_t>& out, std::uint32_t v)
{
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>(v >> shift));
}

// SHA-256 finalized straight into out, with the context wiped: no other copy
// of the digest, or of state derived from the (possibly secret) input, is
// left behind.
void
sha256Into(std::initializer_list<Slice> parts, std::array<std::uint8_t, kScalarLength>& out)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto const& part : parts)
        SHA256_Update(&ctx, part.data(), part.size());
    SHA256_Final(out.data(), &ctx);
    secureErase(&ctx, sizeof(ctx));
}

std::vector<Point>
deriveGenerators(char const* tag)
{
    std::vector<Point> out;
    out.reserve(kMaxBulletproofBits);
    for (std::uint32_t i = 0; i < kMaxBulletproofBits; ++i)
    {
        std::vector<std::uint8_t> seed(tag, tag + std::strlen(tag));
        appendU32(seed, i);
        out.push_back(hashToCurve(makeSlice(seed)));
    }
    return out;
}

}  // namespace

std::optional<Scalar>
Scalar::fromBytes(Slice s)
{
    if (s.size() != kScalarLength)
        return std::nullopt;

    Scalar result;
    std::memcpy(result.bytes_.data(), s.data(), kScalarLength);

    // secp256k1_ec_seckey_verify accepts exactly [1, n-1]; zero is a valid
    // scalar here and is handled separately.
    if (!result.isZero() &&
        secp256k1_ec_seckey_verify(secp256k1Context(), result.bytes_.data()) != 1)
        return std::nullopt;

    return result;
}

Scalar
Scalar::fromUint64(std::uint64_t v)
{
    Scalar result;
    for (std::size_t i = 0; i < sizeof(v); ++i)
        result.bytes_[kScalarLength - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    return result;
}

Scalar
Scalar::fromDigest(std::array<std::uint8_t, kScalarLength> const& digest)
{
    // digest < 2^256 < 2n, so one conditional subtraction of n reduces it.
    Scalar result;
    result.bytes_ = digest;
    reduceOnce(result.bytes_, 0);
    return result;
}

Scalar::~Scalar()
{
    secureErase(bytes_.data(), bytes_.size());
}

Scalar
Scalar::random()
{
    // A uniform 256-bit value is invalid with probability about 2^-128, so
    // repeated failures mean the generator is broken; fail closed.
    Scalar result;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        cryptoPrng()(result.bytes_.data(), result.bytes_.size());
        if (secp256k1_ec_seckey_verify(secp256k1Context(), result.bytes_.data()) == 1)
            return result;
    }
    Throw<std::runtime_error>("confidential: CSPRNG produced invalid scalars");  // LCOV_EXCL_LINE
}

bool
Scalar::isZero() const
{
    return zeroMask(bytes_) != 0;
}

Scalar
operator+(Scalar const& a, Scalar const& b)
{
    Scalar result;
    std::uint32_t carry = 0;
    for (std::size_t i = kScalarLength; i-- > 0;)
    {
        std::uint32_t const sum = std::uint32_t{a.bytes_[i]} + b.bytes_[i] + carry;
        result.bytes_[i] = static_cast<std::uint8_t>(sum);
        carry = sum >> 8;
    }
    // a + b < 2n because both are canonical.
    reduceOnce(result.bytes_, carry);
    return result;
}

Scalar
operator-(Scalar const& a)
{
    // n - a, masked so that -0 is 0 rather than n.
    Scalar result;
    subtract(kGroupOrder, a.bytes_, result.bytes_);
    select(result.bytes_, ScalarBytes{}, zeroMask(a.bytes_));
    return result;
}

Scalar
operator-(Scalar const& a, Scalar const& b)
{
    return a + (-b);
}

Scalar
operator*(Scalar const& a, Scalar const& b)
{
    // tweak_mul returns 0 for a zero operand, and a zero return would take
    // the failure branch below, so zero operands are replaced by one and the
    // product is masked to zero afterwards.
    auto const one = Scalar::fromUint64(1);
    auto const aZero = zeroMask(a.bytes_);
    auto const bZero = zeroMask(b.bytes_);
    Scalar result = a;
    Scalar factor = b;
    select(result.bytes_, one.bytes_, aZero);
    select(factor.bytes_, one.bytes_, bZero);
    if (secp256k1_ec_seckey_tweak_mul(
            secp256k1Context(), result.bytes_.data(), factor.bytes_.data()) != 1)
        secp256k1Failure("seckey_tweak_mul");  // LCOV_EXCL_LINE
    select(result.bytes_, ScalarBytes{}, aZero | bZero);
    return result;
}

Scalar
Scalar::inverse() const
{
    if (isZero())
        Throw<std::domain_error>("confidential: inverse of zero");

    // Fermat: a^(n-2) = a^-1 for prime n.
    auto exponent = kGroupOrder;
    exponent[kScalarLength - 1] -= 2;
    Scalar result = Scalar::fromUint64(1);
    for (auto const byte : exponent)
    {
        for (int bit = 7; bit >= 0; --bit)
        {
            result = result * result;
            if (((byte >> bit) & 1) != 0)
                result = result * *this;
        }
    }
    return result;
}

Point::~Point()
{
    // infinity_ is secret too: it flags a zero scalar in mulSecret.
    secureErase(static_cast<void*>(this), sizeof(*this));
}

Point
Point::generator()
{
    static Point const kG = mulGenerator(Scalar::fromUint64(1));
    return kG;
}

std::optional<Point>
Point::fromBytes(Slice s)
{
    if (s.size() != kEcPointLength || (s[0] != 0x02 && s[0] != 0x03))
        return std::nullopt;

    Point result;
    if (secp256k1_ec_pubkey_parse(secp256k1Context(), &result.pk_, s.data(), s.size()) != 1)
        return std::nullopt;

    result.infinity_ = false;
    return result;
}

std::optional<std::array<std::uint8_t, kEcPointLength>>
Point::bytes() const
{
    if (infinity_)
        return std::nullopt;

    std::array<std::uint8_t, kEcPointLength> out{};
    std::size_t len = out.size();
    if (secp256k1_ec_pubkey_serialize(
            secp256k1Context(), out.data(), &len, &pk_, SECP256K1_EC_COMPRESSED) != 1 ||
        len != out.size())
        secp256k1Failure("serialize");  // LCOV_EXCL_LINE

    return out;
}

Point
operator+(Point const& a, Point const& b)
{
    if (a.infinity_)
        return b;
    if (b.infinity_)
        return a;

    // secp256k1_ec_pubkey_combine fails only when the sum is the point at
    // infinity, because both inputs are valid points.
    std::array<secp256k1_pubkey const*, 2> const ins{&a.pk_, &b.pk_};
    Point result;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &result.pk_, ins.data(), ins.size()) == 1)
        result.infinity_ = false;
    return result;
}

Point
operator-(Point const& a)
{
    Point result = a;
    if (!result.infinity_ && secp256k1_ec_pubkey_negate(secp256k1Context(), &result.pk_) != 1)
        secp256k1Failure("negate");  // LCOV_EXCL_LINE
    return result;
}

Point
operator-(Point const& a, Point const& b)
{
    return a + (-b);
}

Point
operator*(Scalar const& k, Point const& p)
{
    if (p.infinity_ || k.isZero())
        return Point{};

    Point result = p;
    if (secp256k1_ec_pubkey_tweak_mul(secp256k1Context(), &result.pk_, k.bytes().data()) != 1)
        secp256k1Failure("tweak_mul");  // LCOV_EXCL_LINE
    return result;
}

bool
operator==(Point const& a, Point const& b)
{
    if (a.infinity_ || b.infinity_)
        return a.infinity_ == b.infinity_;
    return secp256k1_ec_pubkey_cmp(secp256k1Context(), &a.pk_, &b.pk_) == 0;
}

Point
mulSecret(Scalar const& k, Point const& p)
{
    if (p.infinity_)
        return Point{};

    // secp256k1_ecdh rejects a zero scalar, so zero is replaced by one and
    // the product flagged as the identity: every scalar costs the same.
    auto const kZero = zeroMask(k.bytes());
    ScalarBytes scalar = k.bytes();
    select(scalar, Scalar::fromUint64(1).bytes(), kZero);

    // secp256k1_ecdh multiplies with the constant-time ecmult_const; this hash
    // callback hands back the affine product instead of hashing it.
    auto const copyPoint =
        [](unsigned char* out, unsigned char const* x32, unsigned char const* y32, void*) -> int {
        out[0] = 0x04;
        std::memcpy(out + 1, x32, 32);
        std::memcpy(out + 33, y32, 32);
        return 1;
    };
    std::array<std::uint8_t, 65> uncompressed{};
    Point result;
    if (secp256k1_ecdh(
            secp256k1Context(), uncompressed.data(), &p.pk_, scalar.data(), copyPoint, nullptr) !=
            1 ||
        secp256k1_ec_pubkey_parse(
            secp256k1Context(), &result.pk_, uncompressed.data(), uncompressed.size()) != 1)
        secp256k1Failure("ecdh");  // LCOV_EXCL_LINE
    secureErase(uncompressed.data(), uncompressed.size());
    secureErase(scalar.data(), scalar.size());
    result.infinity_ = (kZero & 1) != 0;
    return result;
}

Point
mulGenerator(Scalar const& k)
{
    // As in mulSecret, a zero scalar is multiplied as one and flagged.
    auto const kZero = zeroMask(k.bytes());
    ScalarBytes scalar = k.bytes();
    select(scalar, Scalar::fromUint64(1).bytes(), kZero);

    Point result;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &result.pk_, scalar.data()) != 1)
        secp256k1Failure("create");  // LCOV_EXCL_LINE
    secureErase(scalar.data(), scalar.size());
    result.infinity_ = (kZero & 1) != 0;
    return result;
}

Point
multiScalarMul(std::span<Scalar const> scalars, std::span<Point const> points)
{
    if (scalars.size() != points.size())
        Throw<std::invalid_argument>("confidential: multiScalarMul size mismatch");

    std::vector<Point> terms;
    terms.reserve(scalars.size());
    for (std::size_t i = 0; i < scalars.size(); ++i)
    {
        auto term = scalars[i] * points[i];
        if (!term.infinity_)
            terms.push_back(term);
    }
    if (terms.empty())
        return Point{};

    std::vector<secp256k1_pubkey const*> ins;
    ins.reserve(terms.size());
    for (auto const& t : terms)
        ins.push_back(&t.pk_);

    // As in operator+, combine fails only when the sum is the identity.
    Point result;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &result.pk_, ins.data(), ins.size()) == 1)
        result.infinity_ = false;
    return result;
}

Point
sumPoints(std::span<Point const> points)
{
    std::vector<secp256k1_pubkey const*> ins;
    ins.reserve(points.size());
    for (auto const& p : points)
    {
        if (!p.infinity_)
            ins.push_back(&p.pk_);
    }
    Point result;
    if (!ins.empty() &&
        secp256k1_ec_pubkey_combine(secp256k1Context(), &result.pk_, ins.data(), ins.size()) == 1)
        result.infinity_ = false;
    return result;
}

HedgedNonces::HedgedNonces(
    std::string_view tag,
    std::initializer_list<Scalar> secrets,
    uint256 const& contextID)
{
    // Sized up front so no reallocation leaves unwiped copies of the secrets
    // behind.
    seed_.reserve(tag.size() + secrets.size() * kScalarLength + 2 * 32);
    seed_.assign(tag.begin(), tag.end());
    for (auto const& secret : secrets)
        seed_.insert(seed_.end(), secret.bytes().begin(), secret.bytes().end());
    seed_.insert(seed_.end(), contextID.begin(), contextID.end());
    std::array<std::uint8_t, 32> entropy{};
    cryptoPrng()(entropy.data(), entropy.size());
    seed_.insert(seed_.end(), entropy.begin(), entropy.end());
    secureErase(entropy.data(), entropy.size());
}

HedgedNonces::~HedgedNonces()
{
    secureErase(seed_.data(), seed_.size());
}

Scalar
HedgedNonces::next()
{
    for (;;)
    {
        std::vector<std::uint8_t> ctr;
        appendU32(ctr, counter_++);
        std::array<std::uint8_t, kScalarLength> digest{};
        sha256Into({makeSlice(seed_), makeSlice(ctr)}, digest);
        auto const k = Scalar::fromDigest(digest);
        secureErase(digest.data(), digest.size());
        if (!k.isZero())
            return k;
    }
}

std::array<std::uint8_t, kScalarLength>
sha256(std::initializer_list<Slice> parts)
{
    // Secret inputs (the hedged nonces) use sha256Into, whose caller wipes
    // the only copy of the digest.
    std::array<std::uint8_t, kScalarLength> out{};
    sha256Into(parts, out);
    return out;
}

Point
hashToCurve(Slice seed)
{
    std::array<std::uint8_t, kEcPointLength> candidate{};
    candidate[0] = 0x02;
    // About half of all x coordinates are on the curve, so 256 attempts
    // fail with probability 2^-256.
    for (std::uint32_t ctr = 0; ctr < 256; ++ctr)
    {
        std::vector<std::uint8_t> counter;
        appendU32(counter, ctr);
        auto const x = sha256({seed, makeSlice(counter)});
        std::memcpy(candidate.data() + 1, x.data(), x.size());
        if (auto const p = Point::fromBytes(makeSlice(candidate)))
            return *p;
    }
    Throw<std::runtime_error>("confidential: hashToCurve found no point");  // LCOV_EXCL_LINE
}

bool
distinctUpToSign(std::span<Point const> points)
{
    std::vector<std::array<std::uint8_t, kScalarLength>> xs;
    xs.reserve(points.size());
    for (auto const& p : points)
    {
        auto const b = p.bytes();
        if (!b)
            return false;
        auto& x = xs.emplace_back();
        std::memcpy(x.data(), b->data() + 1, x.size());
    }
    std::ranges::sort(xs);
    return std::ranges::adjacent_find(xs) == xs.end();
}

namespace {

struct Generators
{
    Point h;
    Point u;
    std::vector<Point> g;
    std::vector<Point> hVec;
};

Generators const&
generators()
{
    static Generators const kGenerators = [] {
        Generators out{
            .h = hashToCurve(asSlice("CMPT_PEDERSEN_H")),
            .u = hashToCurve(asSlice("CMPT_BP_U")),
            .g = deriveGenerators("CMPT_BP_G"),
            .hVec = deriveGenerators("CMPT_BP_H")};

        // Commitments bind only while no relation between the generators is
        // known; a repeat (or a negation) of one is such a relation.
        std::vector<Point> all{Point::generator(), out.h, out.u};
        all.insert(all.end(), out.g.begin(), out.g.end());
        all.insert(all.end(), out.hVec.begin(), out.hVec.end());
        if (!distinctUpToSign(all))
            Throw<std::logic_error>("confidential: generators collide");  // LCOV_EXCL_LINE
        return out;
    }();
    return kGenerators;
}

}  // namespace

Point const&
pedersenGenerator()
{
    return generators().h;
}

Point const&
innerProductGenerator()
{
    return generators().u;
}

std::span<Point const>
bulletproofGeneratorsG()
{
    return generators().g;
}

std::span<Point const>
bulletproofGeneratorsH()
{
    return generators().hVec;
}

namespace {

// v·G + p, computed as (v + 1)·G + p - G: a zero v (an empty balance, a
// zero amount) would otherwise yield an identity term that addition skips.
// Degenerate inputs still take the identity path: v = n - 1, and p the
// identity (a zero blinding or randomness, which proveRange rejects and which
// makes the output reveal the message anyway).
Point
addGeneratorMultiple(Scalar const& v, Point const& p)
{
    std::array<Point, 3> const terms{
        mulGenerator(v + Scalar::fromUint64(1)), p, -Point::generator()};
    return sumPoints(terms);
}

}  // namespace

Point
pedersenCommit(Scalar const& value, Scalar const& blinding)
{
    return addGeneratorMultiple(value, mulSecret(blinding, pedersenGenerator()));
}

bool
isValidPoint(Slice s)
{
    return Point::fromBytes(s).has_value();
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::fromBytes(Slice s)
{
    if (s.size() != kElGamalCiphertextLength)
        return std::nullopt;

    auto const c1 = Point::fromBytes(Slice(s.data(), kEcPointLength));
    auto const c2 = Point::fromBytes(Slice(s.data() + kEcPointLength, kEcPointLength));
    if (!c1 || !c2)
        return std::nullopt;

    return ElGamalCiphertext{.c1 = *c1, .c2 = *c2};
}

std::optional<Buffer>
ElGamalCiphertext::toBuffer() const
{
    auto const b1 = c1.bytes();
    auto const b2 = c2.bytes();
    if (!b1 || !b2)
        return std::nullopt;

    Buffer out(kElGamalCiphertextLength);
    std::memcpy(out.data(), b1->data(), kEcPointLength);
    std::memcpy(out.data() + kEcPointLength, b2->data(), kEcPointLength);
    return out;
}

ElGamalCiphertext
operator+(ElGamalCiphertext const& a, ElGamalCiphertext const& b)
{
    return ElGamalCiphertext{.c1 = a.c1 + b.c1, .c2 = a.c2 + b.c2};
}

ElGamalCiphertext
operator-(ElGamalCiphertext const& a, ElGamalCiphertext const& b)
{
    return ElGamalCiphertext{.c1 = a.c1 - b.c1, .c2 = a.c2 - b.c2};
}

ElGamalCiphertext
elGamalEncrypt(Scalar const& m, Scalar const& r, Point const& pk)
{
    if (pk.isInfinity())
        Throw<std::invalid_argument>("confidential: encryption key is the point at infinity");
    return ElGamalCiphertext{.c1 = mulGenerator(r), .c2 = addGeneratorMultiple(m, mulSecret(r, pk))};
}

Scalar
encryptedZeroRandomness(AccountID const& account, MPTID const& issuance)
{
    auto const issuer = MPTIssue{issuance}.getIssuer();
    auto const r = Scalar::fromDigest(sha256(
        {asSlice("EncZero"),
         Slice(account.data(), account.size()),
         Slice(issuer.data(), issuer.size()),
         Slice(issuance.data(), issuance.size())}));
    // A zero digest mod n happens with probability 2^-256.
    return r.isZero() ? Scalar::fromUint64(1) : r;
}

ElGamalCiphertext
encryptedZero(AccountID const& account, MPTID const& issuance, Point const& pk)
{
    return elGamalEncrypt(Scalar{}, encryptedZeroRandomness(account, issuance), pk);
}

uint256
transactionContextID(
    std::uint16_t txType,
    AccountID const& account,
    MPTID const& issuance,
    std::uint32_t sequence,
    AccountID const& party,
    std::uint32_t version)
{
    std::array<std::uint8_t, 2> const type{
        static_cast<std::uint8_t>(txType >> 8), static_cast<std::uint8_t>(txType)};
    std::vector<std::uint8_t> seq;
    appendU32(seq, sequence);
    std::vector<std::uint8_t> ver;
    appendU32(ver, version);
    auto const digest = sha256(
        {makeSlice(type),
         Slice(account.data(), account.size()),
         Slice(issuance.data(), issuance.size()),
         makeSlice(seq),
         Slice(party.data(), party.size()),
         makeSlice(ver)});
    return uint256::fromVoid(digest.data());
}

bool
verifyElGamalEncryption(
    ElGamalCiphertext const& ct,
    Scalar const& m,
    Scalar const& r,
    Point const& pk)
{
    if (pk.isInfinity() || r.isZero() || ct.c1.isInfinity() || ct.c2.isInfinity())
        return false;
    return ct == elGamalEncrypt(m, r, pk);
}

}  // namespace xrpl::confidential
