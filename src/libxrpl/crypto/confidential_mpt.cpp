#include <xrpl/crypto/confidential_mpt.h>

#include <xrpl/beast/utility/rngfill.h>
#include <xrpl/crypto/csprng.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <secp256k1.h>

#include <cstdlib>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

namespace xrpl {
namespace confidential_mpt {
namespace {

secp256k1_context const*
secpCtx() noexcept
{
    struct Holder
    {
        secp256k1_context* impl;
        Holder() : impl(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        {
        }
        ~Holder()
        {
            secp256k1_context_destroy(impl);
        }
    };
    static Holder const holder;
    return holder.impl;
}

Slice
asSlice(Point const& p) noexcept
{
    return Slice{p.data(), p.size()};
}

Slice
asSlice(Scalar const& s) noexcept
{
    return Slice{s.data(), s.size()};
}

Scalar
u64ToScalar(std::uint64_t v) noexcept
{
    Scalar out{};
    for (std::size_t i = 0; i < 8; ++i)
        out[31 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    return out;
}

bool
scalarEqual(Scalar const& a, Scalar const& b) noexcept
{
    return CRYPTO_memcmp(a.data(), b.data(), kScalarBytes) == 0;
}

bool
randomScalar(Scalar& out) noexcept
{
    for (int i = 0; i < 128; ++i)
    {
        beast::rngfill(out.data(), out.size(), cryptoPrng());
        if (secp256k1_ec_seckey_verify(secpCtx(), out.data()) == 1)
            return true;
    }
    return false;
}

bool
loadPoint(Point const& in, secp256k1_pubkey& out) noexcept
{
    return secp256k1_ec_pubkey_parse(secpCtx(), &out, in.data(), in.size()) == 1;
}

std::optional<Point>
storePoint(secp256k1_pubkey const& pk) noexcept
{
    Point out{};
    std::size_t len = out.size();
    if (secp256k1_ec_pubkey_serialize(secpCtx(), out.data(), &len, &pk, SECP256K1_EC_COMPRESSED) !=
            1 ||
        len != kPointBytes)
        return std::nullopt;
    return out;
}

std::optional<Point>
doMulBase(Scalar const& k) noexcept
{
    if (secp256k1_ec_seckey_verify(secpCtx(), k.data()) != 1)
        return std::nullopt;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(secpCtx(), &pk, k.data()) != 1)
        return std::nullopt;
    return storePoint(pk);
}

std::optional<Point>
doMul(Point const& p, Scalar const& k) noexcept
{
    if (secp256k1_ec_seckey_verify(secpCtx(), k.data()) != 1)
        return std::nullopt;
    secp256k1_pubkey pk;
    if (!loadPoint(p, pk))
        return std::nullopt;
    if (secp256k1_ec_pubkey_tweak_mul(secpCtx(), &pk, k.data()) != 1)
        return std::nullopt;
    return storePoint(pk);
}

std::optional<Point>
doAdd(Point const& a, Point const& b) noexcept
{
    secp256k1_pubkey pa;
    secp256k1_pubkey pb;
    if (!loadPoint(a, pa) || !loadPoint(b, pb))
        return std::nullopt;
    secp256k1_pubkey const* ptrs[2] = {&pa, &pb};
    secp256k1_pubkey sum;
    if (secp256k1_ec_pubkey_combine(secpCtx(), &sum, ptrs, 2) != 1)
        return std::nullopt;
    return storePoint(sum);
}

std::optional<Point>
doSub(Point const& a, Point const& b) noexcept
{
    secp256k1_pubkey pa;
    secp256k1_pubkey pb;
    if (!loadPoint(a, pa) || !loadPoint(b, pb))
        return std::nullopt;
    if (secp256k1_ec_pubkey_negate(secpCtx(), &pb) != 1)
        return std::nullopt;
    secp256k1_pubkey const* ptrs[2] = {&pa, &pb};
    secp256k1_pubkey sum;
    if (secp256k1_ec_pubkey_combine(secpCtx(), &sum, ptrs, 2) != 1)
        return std::nullopt;
    return storePoint(sum);
}

/** m*G; nullopt denotes the identity (m == 0). */
std::optional<Point>
mG(std::uint64_t m) noexcept
{
    if (m == 0)
        return std::nullopt;
    return doMulBase(u64ToScalar(m));
}

std::optional<Point>
addMaybeMG(std::optional<Point> const& maybeMG, Point const& other) noexcept
{
    if (!maybeMG)
        return other;
    return doAdd(*maybeMG, other);
}

/**
 * Provisional Fiat–Shamir hash.
 *
 * The Confidential MPT documents define ordered Fiat–Shamir transcripts but
 * omit the hash algorithm and the encoding that reduces a digest into Z_q.
 * This module therefore uses XRPL SHA-512Half over raw ordered byte
 * concatenation (domain tag, then compressed points / scalars / context in
 * the order required by each proof) as an explicitly provisional choice.
 * The 32-byte digest is accepted only when it already lies in [1, q-1]; a
 * modular-reduction encoding is not specified by the supplied documents and
 * is not invented here.
 */
class Transcript
{
    SHA512_CTX sha_{};

public:
    Transcript()
    {
        SHA512_Init(&sha_);
    }

    void
    append(void const* data, std::size_t len) noexcept
    {
        if (len != 0)
            SHA512_Update(&sha_, data, len);
    }

    void
    append(Slice s) noexcept
    {
        append(s.data(), s.size());
    }

    void
    append(std::string_view s) noexcept
    {
        append(s.data(), s.size());
    }

    void
    appendPoint(Point const& p) noexcept
    {
        append(p.data(), p.size());
    }

    std::optional<Scalar>
    challenge() noexcept
    {
        unsigned char dig[SHA512_DIGEST_LENGTH];
        SHA512_Final(dig, &sha_);
        Scalar out{};
        std::memcpy(out.data(), dig, kScalarBytes);
        if (secp256k1_ec_seckey_verify(secpCtx(), out.data()) != 1)
            return std::nullopt;
        return out;
    }
};

Scalar
scalarAt(Slice proof, std::size_t index) noexcept
{
    Scalar s{};
    std::memcpy(s.data(), proof.data() + index * kScalarBytes, kScalarBytes);
    return s;
}

bool
scalarsValid(Slice proof, std::size_t count) noexcept
{
    if (proof.size() != count * kScalarBytes)
        return false;
    for (std::size_t i = 0; i < count; ++i)
    {
        if (!isValidScalar(Slice{proof.data() + i * kScalarBytes, kScalarBytes}))
            return false;
    }
    return true;
}

std::optional<Scalar>
sigmaRespond(Scalar const& e, Scalar const& a, Scalar const& wit) noexcept
{
    // z = a + e * wit
    Scalar z = e;
    if (secp256k1_ec_seckey_tweak_mul(secpCtx(), z.data(), wit.data()) != 1)
        return std::nullopt;
    if (secp256k1_ec_seckey_tweak_add(secpCtx(), z.data(), a.data()) != 1)
        return std::nullopt;
    return z;
}

std::optional<Scalar>
sigmaRespondAmount(Scalar const& e, Scalar const& a, std::uint64_t value) noexcept
{
    if (value == 0)
        return a;
    return sigmaRespond(e, a, u64ToScalar(value));
}

Point
makePedersenH() noexcept
{
    constexpr std::string_view kTag = "XRPL_CONFIDENTIAL_MPT_PEDERSEN_H";
    for (std::uint32_t c = 0; c < 4096; ++c)
    {
        unsigned char dig[SHA512_DIGEST_LENGTH];
        SHA512_CTX sha;
        SHA512_Init(&sha);
        SHA512_Update(&sha, kTag.data(), kTag.size());
        unsigned char ctr[4] = {
            static_cast<unsigned char>((c >> 24) & 0xff),
            static_cast<unsigned char>((c >> 16) & 0xff),
            static_cast<unsigned char>((c >> 8) & 0xff),
            static_cast<unsigned char>(c & 0xff),
        };
        SHA512_Update(&sha, ctr, sizeof(ctr));
        SHA512_Final(dig, &sha);

        for (unsigned char prefix : {std::uint8_t{2}, std::uint8_t{3}})
        {
            Point cand{};
            cand[0] = prefix;
            std::memcpy(cand.data() + 1, dig, 32);
            if (isValidCompressedPoint(asSlice(cand)))
                return cand;
        }
    }
    std::abort();
}

bool
sendWellFormed(SendPublicInput const& x) noexcept
{
    if (x.recipientKeys.empty() || x.recipientKeys.size() != x.c2.size())
        return false;
    auto good = [](Point const& p) { return isValidCompressedPoint(asSlice(p)); };
    if (!good(x.senderKey) || !good(x.c1) || !good(x.amountCommitment) ||
        !good(x.balanceCommitment) || !good(x.balanceC1) || !good(x.balanceC2))
        return false;
    for (auto const& p : x.recipientKeys)
    {
        if (!good(p))
            return false;
    }
    for (auto const& p : x.c2)
    {
        if (!good(p))
            return false;
    }
    return true;
}

void
appendSendPublic(Transcript& tr, SendPublicInput const& x) noexcept
{
    tr.append(kDomainSend);
    for (auto const& p : x.recipientKeys)
        tr.appendPoint(p);
    tr.appendPoint(x.senderKey);
    tr.appendPoint(x.c1);
    for (auto const& c2 : x.c2)
        tr.appendPoint(c2);
    tr.appendPoint(x.amountCommitment);
    tr.appendPoint(x.balanceCommitment);
    tr.appendPoint(x.balanceC1);
    tr.appendPoint(x.balanceC2);
    // H is part of relation R_send's public statement, but Equation (26)'s
    // normative transcript order omits it.
}

}  // namespace

//------------------------------------------------------------------------------

bool
isValidCompressedPoint(Slice data) noexcept
{
    if (data.size() != kPointBytes)
        return false;
    secp256k1_pubkey pk;
    return secp256k1_ec_pubkey_parse(secpCtx(), &pk, data.data(), data.size()) == 1;
}

bool
isValidScalar(Slice data) noexcept
{
    if (data.size() != kScalarBytes)
        return false;
    return secp256k1_ec_seckey_verify(secpCtx(), data.data()) == 1;
}

std::optional<Scalar>
reduceScalar(Slice data) noexcept
{
    if (data.size() != kScalarBytes)
        return std::nullopt;

    BIGNUM* value = BN_bin2bn(data.data(), static_cast<int>(data.size()), nullptr);
    BIGNUM* order = nullptr;
    BIGNUM* reduced = BN_new();
    BN_CTX* context = BN_CTX_new();
    BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    if (!value || !order || !reduced || !context || !BN_mod(reduced, value, order, context) ||
        BN_is_zero(reduced))
    {
        BN_free(value);
        BN_free(order);
        BN_free(reduced);
        BN_CTX_free(context);
        return std::nullopt;
    }

    Scalar result{};
    bool const ok = BN_bn2binpad(reduced, result.data(), static_cast<int>(result.size())) ==
        static_cast<int>(result.size());
    BN_free(value);
    BN_free(order);
    BN_free(reduced);
    BN_CTX_free(context);
    return ok ? std::optional<Scalar>{result} : std::nullopt;
}

std::optional<Ciphertext>
parseCiphertext(Slice data) noexcept
{
    if (data.size() != kCiphertextBytes)
        return std::nullopt;
    Point c1{};
    Point c2{};
    std::memcpy(c1.data(), data.data(), kPointBytes);
    std::memcpy(c2.data(), data.data() + kPointBytes, kPointBytes);
    if (!isValidCompressedPoint(asSlice(c1)) || !isValidCompressedPoint(asSlice(c2)))
        return std::nullopt;
    return serializeCiphertext(c1, c2);
}

Ciphertext
serializeCiphertext(Point const& c1, Point const& c2) noexcept
{
    Ciphertext out{};
    std::memcpy(out.data(), c1.data(), kPointBytes);
    std::memcpy(out.data() + kPointBytes, c2.data(), kPointBytes);
    return out;
}

Point
ciphertextC1(Ciphertext const& ct) noexcept
{
    Point p{};
    std::memcpy(p.data(), ct.data(), kPointBytes);
    return p;
}

Point
ciphertextC2(Ciphertext const& ct) noexcept
{
    Point p{};
    std::memcpy(p.data(), ct.data() + kPointBytes, kPointBytes);
    return p;
}

std::optional<Point>
pointAdd(Point const& p, Point const& q) noexcept
{
    return doAdd(p, q);
}

std::optional<Point>
pointSub(Point const& p, Point const& q) noexcept
{
    return doSub(p, q);
}

std::optional<Point>
pointMul(Point const& p, Scalar const& k) noexcept
{
    return doMul(p, k);
}

std::optional<Point>
pointMulBase(Scalar const& k) noexcept
{
    return doMulBase(k);
}

Point const&
pedersenH() noexcept
{
    static Point const h = makePedersenH();
    return h;
}

std::optional<Point>
pedersenCommit(std::uint64_t m, Scalar const& r) noexcept
{
    auto const rH = doMul(pedersenH(), r);
    if (!rH)
        return std::nullopt;
    return addMaybeMG(mG(m), *rH);
}

std::optional<Ciphertext>
encryptAmount(Point const& pk, std::uint64_t m, Scalar const& r) noexcept
{
    auto const c1 = doMulBase(r);
    if (!c1)
        return std::nullopt;
    auto const rPk = doMul(pk, r);
    if (!rPk)
        return std::nullopt;
    auto const c2 = addMaybeMG(mG(m), *rPk);
    if (!c2)
        return std::nullopt;
    return serializeCiphertext(*c1, *c2);
}

bool
verifyCiphertext(Point const& pk, Ciphertext const& ct, std::uint64_t m, Scalar const& r) noexcept
{
    auto const expected = encryptAmount(pk, m, r);
    if (!expected)
        return false;
    return CRYPTO_memcmp(expected->data(), ct.data(), kCiphertextBytes) == 0;
}

std::optional<Ciphertext>
ciphertextAdd(Ciphertext const& a, Ciphertext const& b) noexcept
{
    auto const c1 = doAdd(ciphertextC1(a), ciphertextC1(b));
    auto const c2 = doAdd(ciphertextC2(a), ciphertextC2(b));
    if (!c1 || !c2)
        return std::nullopt;
    return serializeCiphertext(*c1, *c2);
}

std::optional<Ciphertext>
ciphertextSub(Ciphertext const& a, Ciphertext const& b) noexcept
{
    auto const c1 = doSub(ciphertextC1(a), ciphertextC1(b));
    auto const c2 = doSub(ciphertextC2(a), ciphertextC2(b));
    if (!c1 || !c2)
        return std::nullopt;
    return serializeCiphertext(*c1, *c2);
}

std::optional<Ciphertext>
encryptZero(Point const& pk, Scalar const& r) noexcept
{
    return encryptAmount(pk, 0, r);
}

std::optional<Ciphertext>
rerandomizeWithScalar(Ciphertext const& ct, Point const& pk, Scalar const& e) noexcept
{
    auto const z = encryptZero(pk, e);
    if (!z)
        return std::nullopt;
    return ciphertextAdd(ct, *z);
}

std::optional<ProofPrefixView>
splitSendProof(Slice zkProof) noexcept
{
    if (zkProof.size() < kSendSigmaBytes)
        return std::nullopt;
    return ProofPrefixView{
        Slice{zkProof.data(), kSendSigmaBytes},
        Slice{zkProof.data() + kSendSigmaBytes, zkProof.size() - kSendSigmaBytes}};
}

std::optional<ProofPrefixView>
splitConvertBackProof(Slice zkProof) noexcept
{
    if (zkProof.size() < kConvertBackSigmaBytes)
        return std::nullopt;
    return ProofPrefixView{
        Slice{zkProof.data(), kConvertBackSigmaBytes},
        Slice{zkProof.data() + kConvertBackSigmaBytes, zkProof.size() - kConvertBackSigmaBytes}};
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kKeyRegProofBytes>>
proveKeyRegistration(Scalar const& sk, Point const& pk, Slice context) noexcept
{
    if (!isValidScalar(asSlice(sk)) || !isValidCompressedPoint(asSlice(pk)))
        return std::nullopt;
    auto const expect = doMulBase(sk);
    if (!expect || CRYPTO_memcmp(expect->data(), pk.data(), kPointBytes) != 0)
        return std::nullopt;

    Scalar a{};
    if (!randomScalar(a))
        return std::nullopt;
    auto const A = doMulBase(a);
    if (!A)
        return std::nullopt;

    Transcript tr;
    tr.append(kDomainKeyReg);
    tr.appendPoint(pk);
    tr.appendPoint(*A);
    tr.append(context);
    auto const e = tr.challenge();
    if (!e)
        return std::nullopt;

    auto const s = sigmaRespond(*e, a, sk);
    if (!s)
        return std::nullopt;

    std::array<std::uint8_t, kKeyRegProofBytes> proof{};
    std::memcpy(proof.data(), e->data(), kScalarBytes);
    std::memcpy(proof.data() + kScalarBytes, s->data(), kScalarBytes);
    return proof;
}

bool
verifyKeyRegistration(Point const& pk, Slice proof, Slice context) noexcept
{
    if (!isValidCompressedPoint(asSlice(pk)) || !scalarsValid(proof, 2))
        return false;

    Scalar const e = scalarAt(proof, 0);
    Scalar const s = scalarAt(proof, 1);

    auto const sG = doMulBase(s);
    auto const ePk = doMul(pk, e);
    if (!sG || !ePk)
        return false;
    auto const A = doSub(*sG, *ePk);
    if (!A)
        return false;

    Transcript tr;
    tr.append(kDomainKeyReg);
    tr.appendPoint(pk);
    tr.appendPoint(*A);
    tr.append(context);
    auto const e2 = tr.challenge();
    return e2 && scalarEqual(e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kSendSigmaBytes>>
proveSendSigma(SendPublicInput const& x, SendWitness const& w, Slice context) noexcept
{
    if (!sendWellFormed(x))
        return std::nullopt;
    if (!isValidScalar(asSlice(w.r)) || !isValidScalar(asSlice(w.rho)) ||
        !isValidScalar(asSlice(w.sk)))
        return std::nullopt;

    Scalar am{};
    Scalar ar{};
    Scalar ab{};
    Scalar arho{};
    Scalar ask{};
    if (!randomScalar(am) || !randomScalar(ar) || !randomScalar(ab) || !randomScalar(arho) ||
        !randomScalar(ask))
        return std::nullopt;

    auto const T1 = doMulBase(ar);
    if (!T1)
        return std::nullopt;

    auto const amG = doMulBase(am);
    if (!amG)
        return std::nullopt;

    std::vector<Point> T2;
    T2.reserve(x.recipientKeys.size());
    for (auto const& Pi : x.recipientKeys)
    {
        auto const arPi = doMul(Pi, ar);
        if (!arPi)
            return std::nullopt;
        auto const t2 = doAdd(*amG, *arPi);
        if (!t2)
            return std::nullopt;
        T2.push_back(*t2);
    }

    auto const arH = doMul(pedersenH(), ar);
    if (!arH)
        return std::nullopt;
    auto const Tm = doAdd(*amG, *arH);
    if (!Tm)
        return std::nullopt;

    auto const abG = doMulBase(ab);
    if (!abG)
        return std::nullopt;
    auto const arhoH = doMul(pedersenH(), arho);
    if (!arhoH)
        return std::nullopt;
    auto const Tb = doAdd(*abG, *arhoH);
    if (!Tb)
        return std::nullopt;

    auto const Tsk1 = doMulBase(ask);
    if (!Tsk1)
        return std::nullopt;
    auto const askB1 = doMul(x.balanceC1, ask);
    if (!askB1)
        return std::nullopt;
    auto const Tsk2 = doAdd(*abG, *askB1);
    if (!Tsk2)
        return std::nullopt;

    Transcript tr;
    appendSendPublic(tr, x);
    tr.appendPoint(*T1);
    for (auto const& t2 : T2)
        tr.appendPoint(t2);
    tr.appendPoint(*Tm);
    tr.appendPoint(*Tb);
    tr.appendPoint(*Tsk1);
    tr.appendPoint(*Tsk2);
    tr.append(context);
    auto const e = tr.challenge();
    if (!e)
        return std::nullopt;

    auto const zm = sigmaRespondAmount(*e, am, w.m);
    auto const zr = sigmaRespond(*e, ar, w.r);
    auto const zb = sigmaRespondAmount(*e, ab, w.b);
    auto const zrho = sigmaRespond(*e, arho, w.rho);
    auto const zsk = sigmaRespond(*e, ask, w.sk);
    if (!zm || !zr || !zb || !zrho || !zsk)
        return std::nullopt;

    std::array<std::uint8_t, kSendSigmaBytes> proof{};
    std::memcpy(proof.data() + 0 * kScalarBytes, e->data(), kScalarBytes);
    std::memcpy(proof.data() + 1 * kScalarBytes, zm->data(), kScalarBytes);
    std::memcpy(proof.data() + 2 * kScalarBytes, zr->data(), kScalarBytes);
    std::memcpy(proof.data() + 3 * kScalarBytes, zb->data(), kScalarBytes);
    std::memcpy(proof.data() + 4 * kScalarBytes, zrho->data(), kScalarBytes);
    std::memcpy(proof.data() + 5 * kScalarBytes, zsk->data(), kScalarBytes);
    return proof;
}

SendVerifyResult
verifySendSigma(SendPublicInput const& x, Slice proof, Slice context) noexcept
{
    SendVerifyResult result;
    if (!sendWellFormed(x) || !scalarsValid(proof, 6))
        return result;

    Scalar const e = scalarAt(proof, 0);
    Scalar const zm = scalarAt(proof, 1);
    Scalar const zr = scalarAt(proof, 2);
    Scalar const zb = scalarAt(proof, 3);
    Scalar const zrho = scalarAt(proof, 4);
    Scalar const zsk = scalarAt(proof, 5);

    auto const zrG = doMulBase(zr);
    auto const eC1 = doMul(x.c1, e);
    if (!zrG || !eC1)
        return result;
    auto const T1 = doSub(*zrG, *eC1);
    if (!T1)
        return result;

    auto const zmG = doMulBase(zm);
    if (!zmG)
        return result;

    std::vector<Point> T2;
    T2.reserve(x.recipientKeys.size());
    for (std::size_t i = 0; i < x.recipientKeys.size(); ++i)
    {
        auto const zrPi = doMul(x.recipientKeys[i], zr);
        if (!zrPi)
            return result;
        auto const sum = doAdd(*zmG, *zrPi);
        if (!sum)
            return result;
        auto const eC2 = doMul(x.c2[i], e);
        if (!eC2)
            return result;
        auto const t2 = doSub(*sum, *eC2);
        if (!t2)
            return result;
        T2.push_back(*t2);
    }

    auto const zrH = doMul(pedersenH(), zr);
    if (!zrH)
        return result;
    auto const tmSum = doAdd(*zmG, *zrH);
    if (!tmSum)
        return result;
    auto const ePCm = doMul(x.amountCommitment, e);
    if (!ePCm)
        return result;
    auto const Tm = doSub(*tmSum, *ePCm);
    if (!Tm)
        return result;

    auto const zbG = doMulBase(zb);
    if (!zbG)
        return result;
    auto const zrhoH = doMul(pedersenH(), zrho);
    if (!zrhoH)
        return result;
    auto const tbSum = doAdd(*zbG, *zrhoH);
    if (!tbSum)
        return result;
    auto const ePCb = doMul(x.balanceCommitment, e);
    if (!ePCb)
        return result;
    auto const Tb = doSub(*tbSum, *ePCb);
    if (!Tb)
        return result;

    auto const zskG = doMulBase(zsk);
    auto const ePA = doMul(x.senderKey, e);
    if (!zskG || !ePA)
        return result;
    auto const Tsk1 = doSub(*zskG, *ePA);
    if (!Tsk1)
        return result;

    auto const zskB1 = doMul(x.balanceC1, zsk);
    if (!zskB1)
        return result;
    auto const tsk2Sum = doAdd(*zbG, *zskB1);
    if (!tsk2Sum)
        return result;
    auto const eB2 = doMul(x.balanceC2, e);
    if (!eB2)
        return result;
    auto const Tsk2 = doSub(*tsk2Sum, *eB2);
    if (!Tsk2)
        return result;

    Transcript tr;
    appendSendPublic(tr, x);
    tr.appendPoint(*T1);
    for (auto const& t2 : T2)
        tr.appendPoint(t2);
    tr.appendPoint(*Tm);
    tr.appendPoint(*Tb);
    tr.appendPoint(*Tsk1);
    tr.appendPoint(*Tsk2);
    tr.append(context);
    auto const e2 = tr.challenge();
    if (!e2 || !scalarEqual(e, *e2))
        return result;

    result.ok = true;
    result.challenge = e;
    return result;
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kConvertBackSigmaBytes>>
proveConvertBackSigma(
    ConvertBackPublicInput const& x,
    ConvertBackWitness const& w,
    Slice context) noexcept
{
    if (!isValidCompressedPoint(asSlice(x.holderKey)) ||
        !isValidCompressedPoint(asSlice(x.balanceC1)) ||
        !isValidCompressedPoint(asSlice(x.balanceC2)) ||
        !isValidCompressedPoint(asSlice(x.balanceCommitment)))
        return std::nullopt;
    if (!isValidScalar(asSlice(w.rho)) || !isValidScalar(asSlice(w.sk)))
        return std::nullopt;

    Scalar ab{};
    Scalar arho{};
    Scalar ask{};
    if (!randomScalar(ab) || !randomScalar(arho) || !randomScalar(ask))
        return std::nullopt;

    auto const Tsk1 = doMulBase(ask);
    if (!Tsk1)
        return std::nullopt;
    auto const abG = doMulBase(ab);
    if (!abG)
        return std::nullopt;
    auto const askB1 = doMul(x.balanceC1, ask);
    if (!askB1)
        return std::nullopt;
    auto const Tsk2 = doAdd(*abG, *askB1);
    if (!Tsk2)
        return std::nullopt;
    auto const arhoH = doMul(pedersenH(), arho);
    if (!arhoH)
        return std::nullopt;
    auto const Tb = doAdd(*abG, *arhoH);
    if (!Tb)
        return std::nullopt;

    Transcript tr;
    tr.append(kDomainConvertBack);
    tr.appendPoint(x.holderKey);
    tr.appendPoint(x.balanceC1);
    tr.appendPoint(x.balanceC2);
    tr.appendPoint(x.balanceCommitment);
    // Equation (51) omits H even though R_bal names it in the statement.
    tr.appendPoint(*Tsk1);
    tr.appendPoint(*Tsk2);
    tr.appendPoint(*Tb);
    tr.append(context);
    auto const e = tr.challenge();
    if (!e)
        return std::nullopt;

    auto const zb = sigmaRespondAmount(*e, ab, w.b);
    auto const zrho = sigmaRespond(*e, arho, w.rho);
    auto const zsk = sigmaRespond(*e, ask, w.sk);
    if (!zb || !zrho || !zsk)
        return std::nullopt;

    std::array<std::uint8_t, kConvertBackSigmaBytes> proof{};
    std::memcpy(proof.data() + 0 * kScalarBytes, e->data(), kScalarBytes);
    std::memcpy(proof.data() + 1 * kScalarBytes, zb->data(), kScalarBytes);
    std::memcpy(proof.data() + 2 * kScalarBytes, zrho->data(), kScalarBytes);
    std::memcpy(proof.data() + 3 * kScalarBytes, zsk->data(), kScalarBytes);
    return proof;
}

bool
verifyConvertBackSigma(ConvertBackPublicInput const& x, Slice proof, Slice context) noexcept
{
    if (!isValidCompressedPoint(asSlice(x.holderKey)) ||
        !isValidCompressedPoint(asSlice(x.balanceC1)) ||
        !isValidCompressedPoint(asSlice(x.balanceC2)) ||
        !isValidCompressedPoint(asSlice(x.balanceCommitment)))
        return false;
    if (!scalarsValid(proof, 4))
        return false;

    Scalar const e = scalarAt(proof, 0);
    Scalar const zb = scalarAt(proof, 1);
    Scalar const zrho = scalarAt(proof, 2);
    Scalar const zsk = scalarAt(proof, 3);

    auto const zskG = doMulBase(zsk);
    auto const ePA = doMul(x.holderKey, e);
    if (!zskG || !ePA)
        return false;
    auto const Tsk1 = doSub(*zskG, *ePA);
    if (!Tsk1)
        return false;

    auto const zbG = doMulBase(zb);
    if (!zbG)
        return false;
    auto const zskB1 = doMul(x.balanceC1, zsk);
    if (!zskB1)
        return false;
    auto const tsk2Sum = doAdd(*zbG, *zskB1);
    if (!tsk2Sum)
        return false;
    auto const eB2 = doMul(x.balanceC2, e);
    if (!eB2)
        return false;
    auto const Tsk2 = doSub(*tsk2Sum, *eB2);
    if (!Tsk2)
        return false;

    auto const zrhoH = doMul(pedersenH(), zrho);
    if (!zrhoH)
        return false;
    auto const tbSum = doAdd(*zbG, *zrhoH);
    if (!tbSum)
        return false;
    auto const ePCb = doMul(x.balanceCommitment, e);
    if (!ePCb)
        return false;
    auto const Tb = doSub(*tbSum, *ePCb);
    if (!Tb)
        return false;

    Transcript tr;
    tr.append(kDomainConvertBack);
    tr.appendPoint(x.holderKey);
    tr.appendPoint(x.balanceC1);
    tr.appendPoint(x.balanceC2);
    tr.appendPoint(x.balanceCommitment);
    // Equation (51) omits H even though R_bal names it in the statement.
    tr.appendPoint(*Tsk1);
    tr.appendPoint(*Tsk2);
    tr.appendPoint(*Tb);
    tr.append(context);
    auto const e2 = tr.challenge();
    return e2 && scalarEqual(e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kClawbackProofBytes>>
proveClawback(ClawbackPublicInput const& x, Scalar const& issuerSk, Slice context) noexcept
{
    if (!isValidCompressedPoint(asSlice(x.issuerKey)) || !isValidCompressedPoint(asSlice(x.c1)) ||
        !isValidCompressedPoint(asSlice(x.c2)) || !isValidScalar(asSlice(issuerSk)))
        return std::nullopt;

    Scalar a{};
    if (!randomScalar(a))
        return std::nullopt;
    auto const T1 = doMulBase(a);
    if (!T1)
        return std::nullopt;
    auto const T2 = doMul(x.c1, a);
    if (!T2)
        return std::nullopt;

    std::optional<Point> D;
    std::optional<Point> amountPoint;
    if (x.m == 0)
    {
        D = x.c2;
    }
    else
    {
        amountPoint = doMulBase(u64ToScalar(x.m));
        if (!amountPoint)
            return std::nullopt;
        D = doSub(x.c2, *amountPoint);
        if (!D)
            return std::nullopt;
    }

    Transcript tr;
    tr.append(kDomainClawback);
    tr.appendPoint(x.issuerKey);
    tr.appendPoint(x.c1);
    tr.appendPoint(x.c2);
    // Spec binds m*G; identity has no compressed encoding, so m == 0 uses a
    // fixed ASCII tag instead.
    if (amountPoint)
        tr.appendPoint(*amountPoint);
    else
        tr.append(std::string_view{"AMOUNT_POINT_IDENTITY"});
    tr.appendPoint(*T1);
    tr.appendPoint(*T2);
    tr.append(context);
    auto const e = tr.challenge();
    if (!e)
        return std::nullopt;

    auto const z = sigmaRespond(*e, a, issuerSk);
    if (!z)
        return std::nullopt;

    std::array<std::uint8_t, kClawbackProofBytes> proof{};
    std::memcpy(proof.data(), e->data(), kScalarBytes);
    std::memcpy(proof.data() + kScalarBytes, z->data(), kScalarBytes);
    return proof;
}

bool
verifyClawback(ClawbackPublicInput const& x, Slice proof, Slice context) noexcept
{
    if (!isValidCompressedPoint(asSlice(x.issuerKey)) || !isValidCompressedPoint(asSlice(x.c1)) ||
        !isValidCompressedPoint(asSlice(x.c2)) || !scalarsValid(proof, 2))
        return false;

    Scalar const e = scalarAt(proof, 0);
    Scalar const z = scalarAt(proof, 1);

    auto const zG = doMulBase(z);
    auto const eP = doMul(x.issuerKey, e);
    if (!zG || !eP)
        return false;
    auto const T1 = doSub(*zG, *eP);
    if (!T1)
        return false;

    std::optional<Point> D;
    std::optional<Point> amountPoint;
    if (x.m == 0)
    {
        D = x.c2;
    }
    else
    {
        amountPoint = doMulBase(u64ToScalar(x.m));
        if (!amountPoint)
            return false;
        D = doSub(x.c2, *amountPoint);
        if (!D)
            return false;
    }

    auto const zC1 = doMul(x.c1, z);
    auto const eD = doMul(*D, e);
    if (!zC1 || !eD)
        return false;
    auto const T2 = doSub(*zC1, *eD);
    if (!T2)
        return false;

    Transcript tr;
    tr.append(kDomainClawback);
    tr.appendPoint(x.issuerKey);
    tr.appendPoint(x.c1);
    tr.appendPoint(x.c2);
    if (amountPoint)
        tr.appendPoint(*amountPoint);
    else
        tr.append(std::string_view{"AMOUNT_POINT_IDENTITY"});
    tr.appendPoint(*T1);
    tr.appendPoint(*T2);
    tr.append(context);
    auto const e2 = tr.challenge();
    return e2 && scalarEqual(e, *e2);
}

//------------------------------------------------------------------------------
// Bulletproofs (range proofs)
//------------------------------------------------------------------------------

namespace {

/** Field element in [0, q); zero allowed (unlike wire Scalar challenges). */
using Fq = std::array<std::uint8_t, kScalarBytes>;

BIGNUM*
secpOrder() noexcept
{
    static BIGNUM* n = [] {
        BIGNUM* out = BN_new();
        // secp256k1 group order
        BN_hex2bn(&out, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        return out;
    }();
    return n;
}

BN_CTX*
bnCtx() noexcept
{
    static BN_CTX* ctx = BN_CTX_new();
    return ctx;
}

bool
fqLoad(BIGNUM* out, Fq const& in) noexcept
{
    return BN_bin2bn(in.data(), static_cast<int>(in.size()), out) != nullptr;
}

bool
fqStore(Fq& out, BIGNUM const* in) noexcept
{
    if (BN_is_negative(in) || BN_cmp(in, secpOrder()) >= 0)
        return false;
    return BN_bn2binpad(in, out.data(), static_cast<int>(out.size())) ==
        static_cast<int>(out.size());
}

Fq
fqZero() noexcept
{
    return Fq{};
}

Fq
fqOne() noexcept
{
    Fq out{};
    out[31] = 1;
    return out;
}

bool
fqIsZero(Fq const& a) noexcept
{
    Fq z{};
    return CRYPTO_memcmp(a.data(), z.data(), kScalarBytes) == 0;
}

bool
fqFromScalar(Fq& out, Scalar const& s) noexcept
{
    // Accept only [1, q-1] secret keys as blinds; store as field element.
    if (secp256k1_ec_seckey_verify(secpCtx(), s.data()) != 1)
        return false;
    out = s;
    return true;
}

bool
fqCanonical(Fq const& a) noexcept
{
    BIGNUM* bn = BN_new();
    if (!bn)
        return false;
    bool ok = fqLoad(bn, a) && BN_cmp(bn, secpOrder()) < 0;
    BN_free(bn);
    return ok;
}

/** Strict wire scalar: 32 bytes, big-endian integer in [0, q). */
bool
parseFq(Fq& out, std::uint8_t const* p) noexcept
{
    std::memcpy(out.data(), p, kScalarBytes);
    return fqCanonical(out);
}

bool
fqAdd(Fq& out, Fq const& a, Fq const& b) noexcept
{
    BIGNUM* ba = BN_new();
    BIGNUM* bb = BN_new();
    BIGNUM* r = BN_new();
    if (!ba || !bb || !r)
    {
        BN_free(ba);
        BN_free(bb);
        BN_free(r);
        return false;
    }
    bool ok = fqLoad(ba, a) && fqLoad(bb, b) && BN_mod_add(r, ba, bb, secpOrder(), bnCtx()) &&
        fqStore(out, r);
    BN_free(ba);
    BN_free(bb);
    BN_free(r);
    return ok;
}

bool
fqSub(Fq& out, Fq const& a, Fq const& b) noexcept
{
    BIGNUM* ba = BN_new();
    BIGNUM* bb = BN_new();
    BIGNUM* r = BN_new();
    if (!ba || !bb || !r)
    {
        BN_free(ba);
        BN_free(bb);
        BN_free(r);
        return false;
    }
    bool ok = fqLoad(ba, a) && fqLoad(bb, b) && BN_mod_sub(r, ba, bb, secpOrder(), bnCtx()) &&
        fqStore(out, r);
    BN_free(ba);
    BN_free(bb);
    BN_free(r);
    return ok;
}

bool
fqMul(Fq& out, Fq const& a, Fq const& b) noexcept
{
    BIGNUM* ba = BN_new();
    BIGNUM* bb = BN_new();
    BIGNUM* r = BN_new();
    if (!ba || !bb || !r)
    {
        BN_free(ba);
        BN_free(bb);
        BN_free(r);
        return false;
    }
    bool ok = fqLoad(ba, a) && fqLoad(bb, b) && BN_mod_mul(r, ba, bb, secpOrder(), bnCtx()) &&
        fqStore(out, r);
    BN_free(ba);
    BN_free(bb);
    BN_free(r);
    return ok;
}

bool
fqNeg(Fq& out, Fq const& a) noexcept
{
    return fqSub(out, fqZero(), a);
}

bool
fqInv(Fq& out, Fq const& a) noexcept
{
    if (fqIsZero(a))
        return false;
    BIGNUM* ba = BN_new();
    BIGNUM* r = BN_new();
    if (!ba || !r)
    {
        BN_free(ba);
        BN_free(r);
        return false;
    }
    bool ok = fqLoad(ba, a) && BN_mod_inverse(r, ba, secpOrder(), bnCtx()) && fqStore(out, r);
    BN_free(ba);
    BN_free(r);
    return ok;
}

Fq
fqU64(std::uint64_t v) noexcept
{
    Fq out{};
    for (std::size_t i = 0; i < 8; ++i)
        out[31 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    return out;
}

bool
fqPow2(Fq& out, std::size_t exp) noexcept
{
    // 2^exp for exp < 64 fits in u64; exp may be up to 63 for bit weights.
    if (exp >= 64)
        return false;
    out = fqU64(std::uint64_t{1} << exp);
    return true;
}

std::optional<Point>
fqMulBase(Fq const& k) noexcept
{
    if (fqIsZero(k))
        return std::nullopt;  // identity
    if (secp256k1_ec_seckey_verify(secpCtx(), k.data()) != 1)
        return std::nullopt;
    return doMulBase(k);
}

std::optional<Point>
fqMulPoint(Point const& p, Fq const& k) noexcept
{
    if (fqIsZero(k))
        return std::nullopt;
    if (secp256k1_ec_seckey_verify(secpCtx(), k.data()) != 1)
        return std::nullopt;
    return doMul(p, k);
}

bool
pointsEqual(Point const& a, Point const& b) noexcept
{
    return CRYPTO_memcmp(a.data(), b.data(), kPointBytes) == 0;
}

/**
 * Multi-scalar mul: sum k_i * P_i. Returns nullopt for the identity
 * (empty sum / all-zero scalars).
 */
std::optional<Point>
msm(std::vector<Point> const& pts, std::vector<Fq> const& ks) noexcept
{
    if (pts.size() != ks.size())
        return std::nullopt;
    std::vector<secp256k1_pubkey> parsed;
    parsed.reserve(pts.size());
    std::vector<secp256k1_pubkey const*> ptrs;
    ptrs.reserve(pts.size());

    for (std::size_t i = 0; i < pts.size(); ++i)
    {
        if (fqIsZero(ks[i]))
            continue;
        auto term = fqMulPoint(pts[i], ks[i]);
        if (!term)
            return std::nullopt;
        secp256k1_pubkey pk;
        if (!loadPoint(*term, pk))
            return std::nullopt;
        parsed.push_back(pk);
    }
    if (parsed.empty())
        return std::nullopt;
    for (auto& pk : parsed)
        ptrs.push_back(&pk);
    secp256k1_pubkey sum;
    if (secp256k1_ec_pubkey_combine(secpCtx(), &sum, ptrs.data(), ptrs.size()) != 1)
        return std::nullopt;
    return storePoint(sum);
}

std::optional<Point>
pointAddOpt(std::optional<Point> const& a, std::optional<Point> const& b) noexcept
{
    if (!a)
        return b;
    if (!b)
        return a;
    return doAdd(*a, *b);
}

std::optional<Point>
pointSubOpt(std::optional<Point> const& a, std::optional<Point> const& b) noexcept
{
    if (!b)
        return a;
    if (!a)
    {
        // identity - b = -b
        secp256k1_pubkey pb;
        if (!loadPoint(*b, pb))
            return std::nullopt;
        if (secp256k1_ec_pubkey_negate(secpCtx(), &pb) != 1)
            return std::nullopt;
        return storePoint(pb);
    }
    return doSub(*a, *b);
}

Point
hashToPoint(std::string_view tag, std::uint32_t index) noexcept
{
    for (std::uint32_t c = 0; c < 4096; ++c)
    {
        unsigned char dig[SHA512_DIGEST_LENGTH];
        SHA512_CTX sha;
        SHA512_Init(&sha);
        SHA512_Update(&sha, tag.data(), tag.size());
        unsigned char idx[4] = {
            static_cast<unsigned char>((index >> 24) & 0xff),
            static_cast<unsigned char>((index >> 16) & 0xff),
            static_cast<unsigned char>((index >> 8) & 0xff),
            static_cast<unsigned char>(index & 0xff),
        };
        SHA512_Update(&sha, idx, sizeof(idx));
        unsigned char ctr[4] = {
            static_cast<unsigned char>((c >> 24) & 0xff),
            static_cast<unsigned char>((c >> 16) & 0xff),
            static_cast<unsigned char>((c >> 8) & 0xff),
            static_cast<unsigned char>(c & 0xff),
        };
        SHA512_Update(&sha, ctr, sizeof(ctr));
        SHA512_Final(dig, &sha);
        for (unsigned char prefix : {std::uint8_t{2}, std::uint8_t{3}})
        {
            Point cand{};
            cand[0] = prefix;
            std::memcpy(cand.data() + 1, dig, 32);
            if (isValidCompressedPoint(asSlice(cand)))
                return cand;
        }
    }
    std::abort();
}

struct BPGens
{
    static constexpr std::size_t kMaxN = 128;  // m=2, n=64
    std::vector<Point> G;
    std::vector<Point> H;
    Point U{};

    BPGens()
    {
        G.reserve(kMaxN);
        H.reserve(kMaxN);
        for (std::uint32_t i = 0; i < kMaxN; ++i)
        {
            G.push_back(hashToPoint("CMPT_BP_G", i));
            H.push_back(hashToPoint("CMPT_BP_H", i));
        }
        U = hashToPoint("CMPT_BP_U", 0);
    }
};

BPGens const&
bpGens() noexcept
{
    static BPGens const g;
    return g;
}

/**
 * Multi-challenge Fiat–Shamir transcript.
 *
 * SPEC GAP: documents omit hash and multi-challenge encoding. Squeeze uses
 * SHA-512Half over a CTX clone of the running state; the 32-byte digest is
 * accepted only in [1, q-1], then absorbed into the running state.
 *
 * SPEC INCONSISTENCY (internal): sigma Transcript::challenge() rejects a
 * digest outside [1, q-1] with nullopt (no retry). This Bulletproof transcript
 * instead increments a 32-bit counter and re-squeezes up to 256 times. Interop
 * requires agreeing whether out-of-range digests are fatal or counter-retried.
 */
class BPTranscript
{
    SHA512_CTX sha_{};

public:
    BPTranscript()
    {
        SHA512_Init(&sha_);
    }

    void
    append(void const* data, std::size_t len) noexcept
    {
        if (len != 0)
            SHA512_Update(&sha_, data, len);
    }

    void
    append(Slice s) noexcept
    {
        append(s.data(), s.size());
    }

    void
    append(std::string_view s) noexcept
    {
        append(s.data(), s.size());
    }

    void
    appendPoint(Point const& p) noexcept
    {
        append(p.data(), p.size());
    }

    void
    appendFq(Fq const& s) noexcept
    {
        append(s.data(), s.size());
    }

    std::optional<Fq>
    challenge() noexcept
    {
        for (std::uint32_t ctr = 0; ctr < 256; ++ctr)
        {
            SHA512_CTX tmp = sha_;
            unsigned char tag[4] = {'C', 'H', 'A', 'L'};
            unsigned char cbytes[4] = {
                static_cast<unsigned char>((ctr >> 24) & 0xff),
                static_cast<unsigned char>((ctr >> 16) & 0xff),
                static_cast<unsigned char>((ctr >> 8) & 0xff),
                static_cast<unsigned char>(ctr & 0xff),
            };
            SHA512_Update(&tmp, tag, sizeof(tag));
            SHA512_Update(&tmp, cbytes, sizeof(cbytes));
            unsigned char dig[SHA512_DIGEST_LENGTH];
            SHA512_Final(dig, &tmp);
            Fq out{};
            std::memcpy(out.data(), dig, kScalarBytes);
            if (secp256k1_ec_seckey_verify(secpCtx(), out.data()) == 1)
            {
                appendFq(out);
                return out;
            }
        }
        return std::nullopt;
    }
};

bool
randomFq(Fq& out) noexcept
{
    Scalar s{};
    if (!randomScalar(s))
        return false;
    out = s;
    return true;
}

bool
innerProduct(Fq& out, std::vector<Fq> const& a, std::vector<Fq> const& b) noexcept
{
    if (a.size() != b.size())
        return false;
    out = fqZero();
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        Fq term{};
        if (!fqMul(term, a[i], b[i]) || !fqAdd(out, out, term))
            return false;
    }
    return true;
}

std::vector<Fq>
powers(Fq const& base, std::size_t n) noexcept
{
    std::vector<Fq> out(n);
    out[0] = fqOne();
    for (std::size_t i = 1; i < n; ++i)
        fqMul(out[i], out[i - 1], base);
    return out;
}

bool
vectorAddScalar(std::vector<Fq>& v, Fq const& s) noexcept
{
    for (auto& x : v)
    {
        if (!fqAdd(x, x, s))
            return false;
    }
    return true;
}

bool
hadamard(std::vector<Fq>& out, std::vector<Fq> const& a, std::vector<Fq> const& b) noexcept
{
    if (a.size() != b.size())
        return false;
    out.resize(a.size());
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (!fqMul(out[i], a[i], b[i]))
            return false;
    }
    return true;
}

std::vector<Fq>
bitVector(std::uint64_t const* values, std::size_t m, std::size_t n) noexcept
{
    std::vector<Fq> aL(m * n, fqZero());
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            if ((values[j] >> i) & 1ull)
                aL[j * n + i] = fqOne();
        }
    }
    return aL;
}

std::vector<Fq>
twoN(std::size_t n) noexcept
{
    std::vector<Fq> out(n);
    for (std::size_t i = 0; i < n; ++i)
        fqPow2(out[i], i);
    return out;
}

std::size_t
log2Exact(std::size_t n) noexcept
{
    std::size_t l = 0;
    while ((std::size_t{1} << l) < n)
        ++l;
    return l;
}

struct BPProofView
{
    Point A{};
    Point S{};
    Point T1{};
    Point T2{};
    Fq tauX{};
    Fq mu{};
    Fq tHat{};
    std::vector<Point> L;
    std::vector<Point> R;
    Fq aHat{};
    Fq bHat{};
};

/**
 * SPEC GAP — serialization order chosen here (not in the supplied docs):
 * A||S||T1||T2||τ_x||μ||t̂||(L_j||R_j)_j||â||b̂
 */
bool
parseBPProof(BPProofView& out, Slice proof, std::size_t rounds) noexcept
{
    std::size_t const nPoints = 4 + 2 * rounds;
    std::size_t const need = nPoints * kPointBytes + 5 * kScalarBytes;
    if (proof.size() != need)
        return false;

    auto rdPoint = [&](std::size_t& off, Point& p) -> bool {
        std::memcpy(p.data(), proof.data() + off, kPointBytes);
        off += kPointBytes;
        return isValidCompressedPoint(asSlice(p));
    };
    auto rdFq = [&](std::size_t& off, Fq& s) -> bool {
        if (!parseFq(s, proof.data() + off))
            return false;
        off += kScalarBytes;
        return true;
    };

    std::size_t off = 0;
    if (!rdPoint(off, out.A) || !rdPoint(off, out.S) || !rdPoint(off, out.T1) ||
        !rdPoint(off, out.T2))
        return false;
    if (!rdFq(off, out.tauX) || !rdFq(off, out.mu) || !rdFq(off, out.tHat))
        return false;
    out.L.resize(rounds);
    out.R.resize(rounds);
    for (std::size_t j = 0; j < rounds; ++j)
    {
        if (!rdPoint(off, out.L[j]) || !rdPoint(off, out.R[j]))
            return false;
    }
    if (!rdFq(off, out.aHat) || !rdFq(off, out.bHat))
        return false;
    return off == proof.size();
}

void
writeBPProof(std::uint8_t* dst, BPProofView const& p, std::size_t rounds) noexcept
{
    std::size_t off = 0;
    auto wrP = [&](Point const& pt) {
        std::memcpy(dst + off, pt.data(), kPointBytes);
        off += kPointBytes;
    };
    auto wrS = [&](Fq const& s) {
        std::memcpy(dst + off, s.data(), kScalarBytes);
        off += kScalarBytes;
    };
    wrP(p.A);
    wrP(p.S);
    wrP(p.T1);
    wrP(p.T2);
    wrS(p.tauX);
    wrS(p.mu);
    wrS(p.tHat);
    for (std::size_t j = 0; j < rounds; ++j)
    {
        wrP(p.L[j]);
        wrP(p.R[j]);
    }
    wrS(p.aHat);
    wrS(p.bHat);
}

bool
deltaYZ(Fq& out, Fq const& y, Fq const& z, std::size_t m, std::size_t n) noexcept
{
    // δ = (z - z^2)<1^N, y^N> - Σ_j z^{j+2} <1^n, 2^n>
    std::size_t const N = m * n;
    auto yN = powers(y, N);
    Fq sumY = fqZero();
    for (auto const& yi : yN)
    {
        if (!fqAdd(sumY, sumY, yi))
            return false;
    }
    Fq z2{};
    if (!fqMul(z2, z, z))
        return false;
    Fq zMz2{};
    if (!fqSub(zMz2, z, z2))
        return false;
    Fq term1{};
    if (!fqMul(term1, zMz2, sumY))
        return false;

    // <1^n, 2^n> = 2^n - 1
    Fq twoNminus1 = fqU64((n == 64) ? ~std::uint64_t{0} : ((std::uint64_t{1} << n) - 1));
    Fq sum2 = fqZero();
    Fq zj = z2;  // z^{2}; first j=1 uses z^{3} = z^2 * z
    for (std::size_t j = 1; j <= m; ++j)
    {
        if (!fqMul(zj, zj, z))  // z^{j+2}: start z^2, after first mul z^3, ...
            return false;
        Fq term{};
        if (!fqMul(term, zj, twoNminus1) || !fqAdd(sum2, sum2, term))
            return false;
    }
    return fqSub(out, term1, sum2);
}

bool
proveRange(
    std::vector<std::uint8_t>& outBytes,
    std::vector<Point> const& commitments,
    std::uint64_t const* values,
    Scalar const* blinds,
    std::size_t m,
    Slice context,
    std::string_view domain) noexcept
{
    constexpr std::size_t n = 64;
    if (m != 1 && m != 2)
        return false;
    if (commitments.size() != m)
        return false;

    std::size_t const N = m * n;
    std::size_t const rounds = log2Exact(N);
    auto const& gens = bpGens();

    std::vector<Fq> gamma(m);
    for (std::size_t j = 0; j < m; ++j)
    {
        if (!isValidCompressedPoint(asSlice(commitments[j])))
            return false;
        if (!fqFromScalar(gamma[j], blinds[j]))
            return false;
        auto expect = pedersenCommit(values[j], blinds[j]);
        if (!expect || !pointsEqual(*expect, commitments[j]))
            return false;
    }

    auto aL = bitVector(values, m, n);
    std::vector<Fq> aR(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqSub(aR[i], aL[i], fqOne()))
            return false;
    }

    Fq alpha{};
    Fq rho{};
    if (!randomFq(alpha) || !randomFq(rho))
        return false;

    std::vector<Fq> sL(N);
    std::vector<Fq> sR(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!randomFq(sL[i]) || !randomFq(sR[i]))
            return false;
    }

    std::vector<Point> Gvec(gens.G.begin(), gens.G.begin() + static_cast<std::ptrdiff_t>(N));
    std::vector<Point> Hvec(gens.H.begin(), gens.H.begin() + static_cast<std::ptrdiff_t>(N));

    auto A1 = msm(Gvec, aL);
    auto A2 = msm(Hvec, aR);
    auto A3 = fqMulPoint(pedersenH(), alpha);
    auto A = pointAddOpt(pointAddOpt(A1, A2), A3);
    if (!A)
        return false;

    auto S1 = msm(Gvec, sL);
    auto S2 = msm(Hvec, sR);
    auto S3 = fqMulPoint(pedersenH(), rho);
    auto S = pointAddOpt(pointAddOpt(S1, S2), S3);
    if (!S)
        return false;

    BPTranscript tr;
    tr.append(domain);
    tr.append(context);
    for (auto const& c : commitments)
        tr.appendPoint(c);
    tr.appendPoint(pedersenH());
    tr.appendPoint(*A);
    tr.appendPoint(*S);
    auto y = tr.challenge();
    auto z = tr.challenge();
    if (!y || !z)
        return false;

    auto yN = powers(*y, N);
    auto yNinv = yN;
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqInv(yNinv[i], yN[i]))
            return false;
    }

    // θ = Σ_{j=1..m} z^{j+1} * (0^{(j-1)n} || 2^n || 0^{(m-j)n})
    std::vector<Fq> theta(N, fqZero());
    auto twos = twoN(n);
    Fq zPow = *z;  // after first mul -> z^2 for j=1
    for (std::size_t j = 1; j <= m; ++j)
    {
        if (!fqMul(zPow, zPow, *z))  // z^{j+1}
            return false;
        for (std::size_t i = 0; i < n; ++i)
        {
            Fq term{};
            if (!fqMul(term, zPow, twos[i]))
                return false;
            std::size_t const idx = (j - 1) * n + i;
            if (!fqAdd(theta[idx], theta[idx], term))
                return false;
        }
    }

    // l0 = aL - z·1, l1 = sL
    // r0 = yN ∘ (aR + z·1) + θ, r1 = yN ∘ sR
    Fq negz{};
    if (!fqNeg(negz, *z))
        return false;
    std::vector<Fq> l0 = aL;
    if (!vectorAddScalar(l0, negz))
        return false;
    std::vector<Fq> const& l1 = sL;

    std::vector<Fq> aRplusZ = aR;
    if (!vectorAddScalar(aRplusZ, *z))
        return false;
    std::vector<Fq> r0;
    if (!hadamard(r0, yN, aRplusZ))
        return false;
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqAdd(r0[i], r0[i], theta[i]))
            return false;
    }
    std::vector<Fq> r1;
    if (!hadamard(r1, yN, sR))
        return false;

    // t1 = <l0,r1>+<l1,r0>, t2 = <l1,r1>  (t0 unused beyond poly definition)
    Fq t2{}, c01{}, c10{}, t1{};
    if (!innerProduct(t2, l1, r1) || !innerProduct(c01, l0, r1) || !innerProduct(c10, l1, r0))
        return false;
    if (!fqAdd(t1, c01, c10))
        return false;

    Fq tau1{}, tau2{};
    if (!randomFq(tau1) || !randomFq(tau2))
        return false;
    auto T1 = pointAddOpt(fqMulBase(t1), fqMulPoint(pedersenH(), tau1));
    auto T2 = pointAddOpt(fqMulBase(t2), fqMulPoint(pedersenH(), tau2));
    if (!T1 || !T2)
        return false;

    tr.appendPoint(*T1);
    tr.appendPoint(*T2);
    auto x = tr.challenge();
    if (!x)
        return false;

    // l = l0 + l1 x, r = r0 + r1 x
    std::vector<Fq> l(N);
    std::vector<Fq> r(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        Fq xl1{}, xr1{};
        if (!fqMul(xl1, l1[i], *x) || !fqAdd(l[i], l0[i], xl1))
            return false;
        if (!fqMul(xr1, r1[i], *x) || !fqAdd(r[i], r0[i], xr1))
            return false;
    }
    Fq tHat{};
    if (!innerProduct(tHat, l, r))
        return false;

    // τ_x = τ2 x^2 + τ1 x + Σ_j z^{j+1} γ_j
    Fq x2{}, tauX{}, t1x{}, t2x2{};
    if (!fqMul(x2, *x, *x) || !fqMul(t1x, tau1, *x) || !fqMul(t2x2, tau2, x2) ||
        !fqAdd(tauX, t1x, t2x2))
        return false;
    Fq zPowG = *z;
    for (std::size_t j = 1; j <= m; ++j)
    {
        if (!fqMul(zPowG, zPowG, *z))  // z^{j+1}
            return false;
        Fq term{};
        if (!fqMul(term, zPowG, gamma[j - 1]) || !fqAdd(tauX, tauX, term))
            return false;
    }

    Fq mu{};
    Fq rhoX{};
    if (!fqMul(rhoX, rho, *x) || !fqAdd(mu, alpha, rhoX))
        return false;

    // H'_i = y^{-i} H_i  (0-based)
    std::vector<Point> Hprime(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        auto hp = fqMulPoint(Hvec[i], yNinv[i]);
        if (!hp)
            return false;
        Hprime[i] = *hp;
    }

    // IPA with U
    tr.appendFq(tauX);
    tr.appendFq(mu);
    tr.appendFq(tHat);
    auto uChal = tr.challenge();
    if (!uChal)
        return false;
    auto U = fqMulPoint(gens.U, *uChal);
    if (!U)
        return false;

    BPProofView proof;
    proof.A = *A;
    proof.S = *S;
    proof.T1 = *T1;
    proof.T2 = *T2;
    proof.tauX = tauX;
    proof.mu = mu;
    proof.tHat = tHat;
    proof.L.resize(rounds);
    proof.R.resize(rounds);

    std::vector<Point> gWork = Gvec;
    std::vector<Point> hWork = Hprime;
    std::vector<Fq> aWork = l;
    std::vector<Fq> bWork = r;
    std::size_t len = N;

    for (std::size_t round = 0; round < rounds; ++round)
    {
        std::size_t const half = len / 2;
        std::vector<Fq> aLo(aWork.begin(), aWork.begin() + half);
        std::vector<Fq> aHi(aWork.begin() + half, aWork.end());
        std::vector<Fq> bLo(bWork.begin(), bWork.begin() + half);
        std::vector<Fq> bHi(bWork.begin() + half, bWork.end());
        std::vector<Point> gLo(gWork.begin(), gWork.begin() + half);
        std::vector<Point> gHi(gWork.begin() + half, gWork.end());
        std::vector<Point> hLo(hWork.begin(), hWork.begin() + half);
        std::vector<Point> hHi(hWork.begin() + half, hWork.end());

        Fq cL{}, cR{};
        if (!innerProduct(cL, aLo, bHi) || !innerProduct(cR, aHi, bLo))
            return false;

        auto L = pointAddOpt(pointAddOpt(msm(gHi, aLo), msm(hLo, bHi)), fqMulPoint(*U, cL));
        auto R = pointAddOpt(pointAddOpt(msm(gLo, aHi), msm(hHi, bLo)), fqMulPoint(*U, cR));
        if (!L || !R)
            return false;
        proof.L[round] = *L;
        proof.R[round] = *R;

        tr.appendPoint(*L);
        tr.appendPoint(*R);
        auto uj = tr.challenge();
        if (!uj)
            return false;
        Fq uinv{};
        if (!fqInv(uinv, *uj))
            return false;

        // a' = aLo*u + aHi*u^{-1}, b' = bLo*u^{-1} + bHi*u
        // G' = u^{-1} G_lo + u G_hi, H' = u H_lo + u^{-1} H_hi
        std::vector<Fq> aNext(half);
        std::vector<Fq> bNext(half);
        std::vector<Point> gNext(half);
        std::vector<Point> hNext(half);
        for (std::size_t i = 0; i < half; ++i)
        {
            Fq t1{}, t2{};
            if (!fqMul(t1, aLo[i], *uj) || !fqMul(t2, aHi[i], uinv) || !fqAdd(aNext[i], t1, t2))
                return false;
            if (!fqMul(t1, bLo[i], uinv) || !fqMul(t2, bHi[i], *uj) || !fqAdd(bNext[i], t1, t2))
                return false;
            auto gTerm = pointAddOpt(fqMulPoint(gLo[i], uinv), fqMulPoint(gHi[i], *uj));
            auto hTerm = pointAddOpt(fqMulPoint(hLo[i], *uj), fqMulPoint(hHi[i], uinv));
            if (!gTerm || !hTerm)
                return false;
            gNext[i] = *gTerm;
            hNext[i] = *hTerm;
        }
        aWork.swap(aNext);
        bWork.swap(bNext);
        gWork.swap(gNext);
        hWork.swap(hNext);
        len = half;
    }

    proof.aHat = aWork[0];
    proof.bHat = bWork[0];

    outBytes.resize((4 + 2 * rounds) * kPointBytes + 5 * kScalarBytes);
    writeBPProof(outBytes.data(), proof, rounds);
    return true;
}

bool
verifyRange(
    std::vector<Point> const& commitments,
    Slice proofBytes,
    Slice context,
    std::string_view domain,
    std::size_t m) noexcept
{
    constexpr std::size_t n = 64;
    if (m != 1 && m != 2)
        return false;
    if (commitments.size() != m)
        return false;
    for (auto const& c : commitments)
    {
        if (!isValidCompressedPoint(asSlice(c)))
            return false;
    }

    std::size_t const N = m * n;
    std::size_t const rounds = log2Exact(N);
    BPProofView proof;
    if (!parseBPProof(proof, proofBytes, rounds))
        return false;

    auto const& gens = bpGens();
    std::vector<Point> Gvec(gens.G.begin(), gens.G.begin() + static_cast<std::ptrdiff_t>(N));
    std::vector<Point> Hvec(gens.H.begin(), gens.H.begin() + static_cast<std::ptrdiff_t>(N));

    BPTranscript tr;
    tr.append(domain);
    tr.append(context);
    for (auto const& c : commitments)
        tr.appendPoint(c);
    tr.appendPoint(pedersenH());
    tr.appendPoint(proof.A);
    tr.appendPoint(proof.S);
    auto y = tr.challenge();
    auto z = tr.challenge();
    if (!y || !z)
        return false;

    tr.appendPoint(proof.T1);
    tr.appendPoint(proof.T2);
    auto x = tr.challenge();
    if (!x)
        return false;

    tr.appendFq(proof.tauX);
    tr.appendFq(proof.mu);
    tr.appendFq(proof.tHat);
    auto uChal = tr.challenge();
    if (!uChal)
        return false;

    // Check t̂ relation:
    // g^{t̂} h^{τ_x} == g^{δ} T1^x T2^{x^2} Π V_j^{z^{j+1}}
    Fq delta{};
    if (!deltaYZ(delta, *y, *z, m, n))
        return false;

    auto lhs = pointAddOpt(fqMulBase(proof.tHat), fqMulPoint(pedersenH(), proof.tauX));
    auto rhs = fqMulBase(delta);
    Fq x2{};
    if (!fqMul(x2, *x, *x))
        return false;
    rhs = pointAddOpt(rhs, fqMulPoint(proof.T1, *x));
    rhs = pointAddOpt(rhs, fqMulPoint(proof.T2, x2));
    Fq zPow = *z;
    for (std::size_t j = 1; j <= m; ++j)
    {
        if (!fqMul(zPow, zPow, *z))
            return false;
        rhs = pointAddOpt(rhs, fqMulPoint(commitments[j - 1], zPow));
    }
    if (!lhs || !rhs || !pointsEqual(*lhs, *rhs))
        return false;

    // Build H' and IPA P
    auto yN = powers(*y, N);
    std::vector<Fq> yNinv(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqInv(yNinv[i], yN[i]))
            return false;
    }
    std::vector<Point> Hprime(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        auto hp = fqMulPoint(Hvec[i], yNinv[i]);
        if (!hp)
            return false;
        Hprime[i] = *hp;
    }

    // θ
    std::vector<Fq> theta(N, fqZero());
    auto twos = twoN(n);
    Fq zPowT = *z;
    for (std::size_t j = 1; j <= m; ++j)
    {
        if (!fqMul(zPowT, zPowT, *z))
            return false;
        for (std::size_t i = 0; i < n; ++i)
        {
            Fq term{};
            if (!fqMul(term, zPowT, twos[i]))
                return false;
            if (!fqAdd(theta[(j - 1) * n + i], theta[(j - 1) * n + i], term))
                return false;
        }
    }

    // exponents for H': z * yN + θ
    std::vector<Fq> hExp(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        Fq zy{};
        if (!fqMul(zy, *z, yN[i]) || !fqAdd(hExp[i], zy, theta[i]))
            return false;
    }

    // P = A + x S - z ΣG + <hExp, H'> + tHat U_chal - mu H
    std::vector<Fq> negZ(N);
    Fq nz{};
    if (!fqNeg(nz, *z))
        return false;
    for (std::size_t i = 0; i < N; ++i)
        negZ[i] = nz;

    auto U = fqMulPoint(gens.U, *uChal);
    if (!U)
        return false;

    auto P = pointAddOpt(
        pointAddOpt(
            pointAddOpt(std::optional<Point>{proof.A}, fqMulPoint(proof.S, *x)), msm(Gvec, negZ)),
        msm(Hprime, hExp));
    P = pointAddOpt(P, fqMulPoint(*U, proof.tHat));
    P = pointSubOpt(P, fqMulPoint(pedersenH(), proof.mu));
    if (!P)
        return false;

    // IPA challenges and s-vector verification
    std::vector<Fq> ujs(rounds);
    for (std::size_t j = 0; j < rounds; ++j)
    {
        tr.appendPoint(proof.L[j]);
        tr.appendPoint(proof.R[j]);
        auto uj = tr.challenge();
        if (!uj)
            return false;
        ujs[j] = *uj;
    }

    // s_i = Π_j u_j^{b} where b is bit of i
    std::vector<Fq> s(N, fqOne());
    for (std::size_t i = 0; i < N; ++i)
    {
        for (std::size_t j = 0; j < rounds; ++j)
        {
            // bit (rounds-1-j) of i: if 1 multiply by u_j, else by u_j^{-1}
            // After prover update G' = u^{-1} G_lo + u G_hi, index i maps:
            // standard: s_i = Π u_j^{2*bit - 1} with bit from high round.
            std::size_t const bit = (i >> (rounds - 1 - j)) & 1u;
            if (bit)
            {
                if (!fqMul(s[i], s[i], ujs[j]))
                    return false;
            }
            else
            {
                Fq inv{};
                if (!fqInv(inv, ujs[j]) || !fqMul(s[i], s[i], inv))
                    return false;
            }
        }
    }

    std::vector<Fq> sInv(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqInv(sInv[i], s[i]))
            return false;
    }

    std::vector<Fq> aS(N);
    std::vector<Fq> bS(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!fqMul(aS[i], proof.aHat, s[i]) || !fqMul(bS[i], proof.bHat, sInv[i]))
            return false;
    }

    Fq ab{};
    if (!fqMul(ab, proof.aHat, proof.bHat))
        return false;

    auto rhsIPA = pointAddOpt(msm(Gvec, aS), msm(Hprime, bS));
    rhsIPA = pointAddOpt(rhsIPA, fqMulPoint(*U, ab));

    // P + Σ (u_j^2 L_j + u_j^{-2} R_j) == â·G_s + b̂·H'_{s^{-1}} + âb̂·U
    auto lhsIPA = P;
    for (std::size_t j = 0; j < rounds; ++j)
    {
        Fq u2{}, ui2{};
        if (!fqMul(u2, ujs[j], ujs[j]) || !fqInv(ui2, u2))
            return false;
        lhsIPA = pointAddOpt(lhsIPA, fqMulPoint(proof.L[j], u2));
        lhsIPA = pointAddOpt(lhsIPA, fqMulPoint(proof.R[j], ui2));
    }
    if (!lhsIPA || !rhsIPA)
        return false;
    return pointsEqual(*lhsIPA, *rhsIPA);
}

}  // namespace

std::optional<std::array<std::uint8_t, kSingleBulletproofBytes>>
proveSingleBulletproof(
    Point const& commitment,
    std::uint64_t value,
    Scalar const& blinding,
    Slice context) noexcept
{
    std::vector<std::uint8_t> bytes;
    std::vector<Point> commits{commitment};
    std::uint64_t values[1] = {value};
    Scalar blinds[1] = {blinding};
    if (!proveRange(bytes, commits, values, blinds, 1, context, kDomainBulletproofSingle))
        return std::nullopt;
    if (bytes.size() != kSingleBulletproofBytes)
        return std::nullopt;
    std::array<std::uint8_t, kSingleBulletproofBytes> out{};
    std::memcpy(out.data(), bytes.data(), bytes.size());
    return out;
}

bool
verifySingleBulletproof(Point const& commitment, Slice proof, Slice context) noexcept
{
    if (proof.size() != kSingleBulletproofBytes)
        return false;
    return verifyRange(std::vector<Point>{commitment}, proof, context, kDomainBulletproofSingle, 1);
}

std::optional<std::array<std::uint8_t, kAggregatedBulletproofBytes>>
proveAggregatedBulletproof(
    Point const& commitment0,
    Point const& commitment1,
    std::uint64_t value0,
    Scalar const& blinding0,
    std::uint64_t value1,
    Scalar const& blinding1,
    Slice context) noexcept
{
    std::vector<std::uint8_t> bytes;
    std::vector<Point> commits{commitment0, commitment1};
    std::uint64_t values[2] = {value0, value1};
    Scalar blinds[2] = {blinding0, blinding1};
    if (!proveRange(bytes, commits, values, blinds, 2, context, kDomainBulletproofAggregated))
        return std::nullopt;
    if (bytes.size() != kAggregatedBulletproofBytes)
        return std::nullopt;
    std::array<std::uint8_t, kAggregatedBulletproofBytes> out{};
    std::memcpy(out.data(), bytes.data(), bytes.size());
    return out;
}

bool
verifyAggregatedBulletproof(
    Point const& commitment0,
    Point const& commitment1,
    Slice proof,
    Slice context) noexcept
{
    if (proof.size() != kAggregatedBulletproofBytes)
        return false;
    return verifyRange(
        std::vector<Point>{commitment0, commitment1},
        proof,
        context,
        kDomainBulletproofAggregated,
        2);
}

}  // namespace confidential_mpt
}  // namespace xrpl
