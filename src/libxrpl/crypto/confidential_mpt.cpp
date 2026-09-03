#include <xrpl/crypto/confidential_mpt.h>

#include <xrpl/beast/utility/rngfill.h>
#include <xrpl/crypto/csprng.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <secp256k1.h>

#include <cstdlib>
#include <cstring>
#include <limits>
#include <string_view>
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
        Holder()
            : impl(secp256k1_context_create(
                  SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
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
    if (secp256k1_ec_pubkey_serialize(
            secpCtx(), out.data(), &len, &pk, SECP256K1_EC_COMPRESSED) != 1 ||
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
    tr.appendPoint(pedersenH());
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
verifyCiphertext(
    Point const& pk,
    Ciphertext const& ct,
    std::uint64_t m,
    Scalar const& r) noexcept
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
rerandomizeWithScalar(Ciphertext const& ct, Point const& pk, Scalar const& e)
    noexcept
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
        Slice{
            zkProof.data() + kConvertBackSigmaBytes,
            zkProof.size() - kConvertBackSigmaBytes}};
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
proveSendSigma(SendPublicInput const& x, SendWitness const& w, Slice context)
    noexcept
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
    if (!randomScalar(am) || !randomScalar(ar) || !randomScalar(ab) ||
        !randomScalar(arho) || !randomScalar(ask))
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
    tr.appendPoint(pedersenH());
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
verifyConvertBackSigma(
    ConvertBackPublicInput const& x,
    Slice proof,
    Slice context) noexcept
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
    tr.appendPoint(pedersenH());
    tr.appendPoint(*Tsk1);
    tr.appendPoint(*Tsk2);
    tr.appendPoint(*Tb);
    tr.append(context);
    auto const e2 = tr.challenge();
    return e2 && scalarEqual(e, *e2);
}

//------------------------------------------------------------------------------

std::optional<std::array<std::uint8_t, kClawbackProofBytes>>
proveClawback(ClawbackPublicInput const& x, Scalar const& issuerSk, Slice context)
    noexcept
{
    if (!isValidCompressedPoint(asSlice(x.issuerKey)) ||
        !isValidCompressedPoint(asSlice(x.c1)) ||
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
    if (!isValidCompressedPoint(asSlice(x.issuerKey)) ||
        !isValidCompressedPoint(asSlice(x.c1)) ||
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

}  // namespace confidential_mpt
}  // namespace xrpl
