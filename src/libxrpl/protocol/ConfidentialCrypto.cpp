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
#include <xrpl/protocol/digest.h>

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
    Scalar result;
    result.bytes_ = digest;
    if (result.isZero() || secp256k1_ec_seckey_verify(secp256k1Context(), digest.data()) == 1)
        return result;

    // n <= digest < 2^256 < 2n, so one subtraction of n reduces it.
    int borrow = 0;
    for (std::size_t i = kScalarLength; i-- > 0;)
    {
        int const diff = int{digest[i]} - int{kGroupOrder[i]} - borrow;
        borrow = diff < 0 ? 1 : 0;
        result.bytes_[i] = static_cast<std::uint8_t>(diff + (borrow << 8));
    }
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
    std::uint8_t acc = 0;
    for (auto const b : bytes_)
        acc |= b;
    return acc == 0;
}

Scalar
operator+(Scalar const& a, Scalar const& b)
{
    if (a.isZero())
        return b;
    if (b.isZero())
        return a;

    // tweak_add rejects only a zero result, since both inputs are canonical.
    Scalar result = a;
    if (secp256k1_ec_seckey_tweak_add(secp256k1Context(), result.bytes_.data(), b.bytes_.data()) !=
        1)
        return Scalar{};
    return result;
}

Scalar
operator-(Scalar const& a)
{
    if (a.isZero())
        return a;

    Scalar result = a;
    if (secp256k1_ec_seckey_negate(secp256k1Context(), result.bytes_.data()) != 1)
        secp256k1Failure("seckey_negate");  // LCOV_EXCL_LINE
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
    if (a.isZero() || b.isZero())
        return Scalar{};

    Scalar result = a;
    if (secp256k1_ec_seckey_tweak_mul(secp256k1Context(), result.bytes_.data(), b.bytes_.data()) !=
        1)
        secp256k1Failure("seckey_tweak_mul");  // LCOV_EXCL_LINE
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

Point
Point::generator()
{
    return mulGenerator(Scalar::fromUint64(1));
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
    if (p.infinity_ || k.isZero())
        return Point{};

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
            secp256k1Context(),
            uncompressed.data(),
            &p.pk_,
            k.bytes().data(),
            copyPoint,
            nullptr) != 1 ||
        secp256k1_ec_pubkey_parse(
            secp256k1Context(), &result.pk_, uncompressed.data(), uncompressed.size()) != 1)
        secp256k1Failure("ecdh");  // LCOV_EXCL_LINE
    secureErase(uncompressed.data(), uncompressed.size());
    result.infinity_ = false;
    return result;
}

Point
mulGenerator(Scalar const& k)
{
    if (k.isZero())
        return Point{};

    Point result;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &result.pk_, k.bytes().data()) != 1)
        secp256k1Failure("create");  // LCOV_EXCL_LINE
    result.infinity_ = false;
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

std::array<std::uint8_t, kScalarLength>
sha256(std::initializer_list<Slice> parts)
{
    sha256_hasher h;
    for (auto const& part : parts)
        h(part.data(), part.size());
    return static_cast<sha256_hasher::result_type>(h);
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

Point const&
pedersenGenerator()
{
    static Point const kH = hashToCurve(asSlice("CMPT_PEDERSEN_H"));
    return kH;
}

Point const&
innerProductGenerator()
{
    static Point const kU = hashToCurve(asSlice("CMPT_BP_U"));
    return kU;
}

std::span<Point const>
bulletproofGeneratorsG()
{
    static std::vector<Point> const kG = deriveGenerators("CMPT_BP_G");
    return kG;
}

std::span<Point const>
bulletproofGeneratorsH()
{
    static std::vector<Point> const kH = deriveGenerators("CMPT_BP_H");
    return kH;
}

Point
pedersenCommit(Scalar const& value, Scalar const& blinding)
{
    return mulGenerator(value) + mulSecret(blinding, pedersenGenerator());
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
    return ElGamalCiphertext{.c1 = mulGenerator(r), .c2 = mulGenerator(m) + mulSecret(r, pk)};
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
