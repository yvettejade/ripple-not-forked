#include <xrpl/protocol/ConfidentialProofs.h>

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/protocol/ConfidentialCrypto.h>
#include <xrpl/protocol/digest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xrpl::confidential {

namespace {

// Fiat-Shamir challenge over a domain tag, statement and commitments, in the
// order given by the specification. Points are 33-byte compressed; a point
// at infinity has no encoding and invalidates the challenge.
class Challenge
{
    sha256_hasher hasher_;
    bool valid_ = true;

public:
    explicit Challenge(std::string_view tag)
    {
        hasher_(tag.data(), tag.size());
    }

    Challenge&
    add(Point const& p)
    {
        auto const b = p.bytes();
        if (!b)
        {
            valid_ = false;
            return *this;
        }
        hasher_(b->data(), b->size());
        return *this;
    }

    Challenge&
    add(uint256 const& v)
    {
        hasher_(v.data(), v.size());
        return *this;
    }

    // The challenge, or nullopt if a point was the identity or the digest
    // reduced to zero (the specification requires e in [1, q-1]).
    std::optional<Scalar>
    finish()
    {
        auto const digest = static_cast<sha256_hasher::result_type>(hasher_);
        if (!valid_)
            return std::nullopt;
        auto const e = Scalar::fromDigest(digest);
        if (e.isZero())
            return std::nullopt;  // LCOV_EXCL_LINE
        return e;
    }
};

// Parse count canonical, non-zero scalars.
std::optional<std::vector<Scalar>>
parseScalars(Slice proof, std::size_t count)
{
    if (proof.size() != count * kScalarLength)
        return std::nullopt;
    std::vector<Scalar> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        auto s = Scalar::fromBytes(Slice(proof.data() + i * kScalarLength, kScalarLength));
        if (!s || s->isZero())
            return std::nullopt;
        out.push_back(*s);
    }
    return out;
}

Buffer
serialize(std::initializer_list<Scalar> scalars)
{
    Buffer out(scalars.size() * kScalarLength);
    std::size_t offset = 0;
    for (auto const& s : scalars)
    {
        std::memcpy(out.data() + offset, s.bytes().data(), kScalarLength);
        offset += kScalarLength;
    }
    return out;
}

bool
constantTimeEqual(Scalar const& a, Scalar const& b)
{
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < kScalarLength; ++i)
        diff |= a.bytes()[i] ^ b.bytes()[i];
    return diff == 0;
}

bool
allNonZero(std::initializer_list<Scalar> scalars)
{
    for (auto const& s : scalars)
    {
        if (s.isZero())
            return false;  // LCOV_EXCL_LINE
    }
    return true;
}

// Honest provers fail to produce a valid transcript with probability about
// 2^-250 per attempt; bound the retries anyway.
constexpr int kMaxProverAttempts = 8;

// LCOV_EXCL_START
[[noreturn]] void
proverFailed()
{
    Throw<std::runtime_error>("confidential: prover could not produce a proof");
}
// LCOV_EXCL_STOP

void
require(bool condition, char const* what)
{
    if (!condition)
        Throw<std::invalid_argument>(std::string("confidential: ") + what);
}

bool
encodable(Point const& p)
{
    return !p.isInfinity();
}

Challenge&
addSendStatement(Challenge& c, SendStatement const& s)
{
    for (auto const& p : s.recipientKeys)
        c.add(p);
    c.add(s.senderKey);
    c.add(s.c1);
    for (auto const& p : s.c2)
        c.add(p);
    c.add(s.amountCommitment).add(s.balanceCommitment).add(s.balance.c1).add(s.balance.c2);
    return c;
}

Challenge&
addBalanceStatement(Challenge& c, BalanceStatement const& s)
{
    return c.add(s.key).add(s.balance.c1).add(s.balance.c2).add(s.balanceCommitment);
}

}  // namespace

Buffer
proveKnowledge(Scalar const& secretKey, uint256 const& contextID)
{
    require(!secretKey.isZero(), "secret key is zero");
    auto const pk = mulGenerator(secretKey);
    HedgedNonces nonces("CMPT_POK_SK_REGISTER", {secretKey}, contextID);
    for (int attempt = 0; attempt < kMaxProverAttempts; ++attempt)
    {
        auto const k = nonces.next();
        auto const e =
            Challenge("CMPT_POK_SK_REGISTER").add(pk).add(mulGenerator(k)).add(contextID).finish();
        if (!e)
            continue;  // LCOV_EXCL_LINE
        auto const s = k + *e * secretKey;
        if (s.isZero())
            continue;  // LCOV_EXCL_LINE
        return serialize({*e, s});
    }
    proverFailed();  // LCOV_EXCL_LINE
}

bool
verifyKnowledge(Point const& publicKey, Slice proof, uint256 const& contextID)
{
    auto const scalars = parseScalars(proof, 2);
    if (!scalars)
        return false;
    auto const& e = (*scalars)[0];
    auto const& s = (*scalars)[1];

    auto const t = mulGenerator(s) - e * publicKey;
    auto const expected =
        Challenge("CMPT_POK_SK_REGISTER").add(publicKey).add(t).add(contextID).finish();
    return expected && constantTimeEqual(*expected, e);
}

Buffer
proveSend(SendStatement const& statement, SendWitness const& w, uint256 const& contextID)
{
    auto const n = statement.recipientKeys.size();
    require(n > 0 && statement.c2.size() == n, "recipient and ciphertext counts differ");
    require(statement.recipientKeys[0] == statement.senderKey, "first recipient is not the sender");
    require(
        std::ranges::all_of(statement.recipientKeys, encodable) &&
            std::ranges::all_of(statement.c2, encodable) && encodable(statement.senderKey) &&
            encodable(statement.c1) && encodable(statement.amountCommitment) &&
            encodable(statement.balanceCommitment) && encodable(statement.balance.c1) &&
            encodable(statement.balance.c2),
        "statement point is the identity");

    auto const& h = pedersenGenerator();
    HedgedNonces nonces(
        "CMPT_SEND_SIGMA",
        {w.amount, w.randomness, w.balance, w.balanceBlinding, w.secretKey},
        contextID);
    for (int attempt = 0; attempt < kMaxProverAttempts; ++attempt)
    {
        auto const am = nonces.next();
        auto const ar = nonces.next();
        auto const ab = nonces.next();
        auto const arho = nonces.next();
        auto const ask = nonces.next();

        Challenge c("CMPT_SEND_SIGMA");
        addSendStatement(c, statement);
        c.add(mulGenerator(ar));
        for (auto const& p : statement.recipientKeys)
            c.add(mulGenerator(am) + mulSecret(ar, p));
        c.add(mulGenerator(am) + mulSecret(ar, h));
        c.add(mulGenerator(ab) + mulSecret(arho, h));
        c.add(mulGenerator(ask));
        c.add(mulGenerator(ab) + mulSecret(ask, statement.balance.c1));
        auto const e = c.add(contextID).finish();
        if (!e)
            continue;  // LCOV_EXCL_LINE

        auto const zm = am + *e * w.amount;
        auto const zr = ar + *e * w.randomness;
        auto const zb = ab + *e * w.balance;
        auto const zrho = arho + *e * w.balanceBlinding;
        auto const zsk = ask + *e * w.secretKey;
        if (!allNonZero({zm, zr, zb, zrho, zsk}))
            continue;  // LCOV_EXCL_LINE
        return serialize({*e, zm, zr, zb, zrho, zsk});
    }
    proverFailed();  // LCOV_EXCL_LINE
}

std::optional<Scalar>
verifySend(SendStatement const& statement, Slice proof, uint256 const& contextID)
{
    auto const n = statement.recipientKeys.size();
    if (n == 0 || statement.c2.size() != n || !(statement.recipientKeys[0] == statement.senderKey))
        return std::nullopt;

    auto const scalars = parseScalars(proof, 6);
    if (!scalars)
        return std::nullopt;
    auto const& e = (*scalars)[0];
    auto const& zm = (*scalars)[1];
    auto const& zr = (*scalars)[2];
    auto const& zb = (*scalars)[3];
    auto const& zrho = (*scalars)[4];
    auto const& zsk = (*scalars)[5];
    auto const& h = pedersenGenerator();

    // Equations (33)-(38).
    Challenge c("CMPT_SEND_SIGMA");
    addSendStatement(c, statement);
    c.add(mulGenerator(zr) - e * statement.c1);
    for (std::size_t i = 0; i < n; ++i)
    {
        c.add(mulGenerator(zm) + zr * statement.recipientKeys[i] - e * statement.c2[i]);
    }
    c.add(mulGenerator(zm) + zr * h - e * statement.amountCommitment);
    c.add(mulGenerator(zb) + zrho * h - e * statement.balanceCommitment);
    c.add(mulGenerator(zsk) - e * statement.senderKey);
    c.add(mulGenerator(zb) + zsk * statement.balance.c1 - e * statement.balance.c2);
    auto const expected = c.add(contextID).finish();
    if (!expected || !constantTimeEqual(*expected, e))
        return std::nullopt;
    return e;
}

Buffer
proveBalance(
    BalanceStatement const& statement,
    Scalar const& balance,
    Scalar const& balanceBlinding,
    Scalar const& secretKey,
    uint256 const& contextID)
{
    require(
        encodable(statement.key) && encodable(statement.balance.c1) &&
            encodable(statement.balance.c2) && encodable(statement.balanceCommitment),
        "statement point is the identity");

    auto const& h = pedersenGenerator();
    HedgedNonces nonces("CMPT_CONVERTBACK_SIGMA", {balance, balanceBlinding, secretKey}, contextID);
    for (int attempt = 0; attempt < kMaxProverAttempts; ++attempt)
    {
        auto const ab = nonces.next();
        auto const arho = nonces.next();
        auto const ask = nonces.next();

        Challenge c("CMPT_CONVERTBACK_SIGMA");
        addBalanceStatement(c, statement);
        c.add(mulGenerator(ask));
        c.add(mulGenerator(ab) + mulSecret(ask, statement.balance.c1));
        c.add(mulGenerator(ab) + mulSecret(arho, h));
        auto const e = c.add(contextID).finish();
        if (!e)
            continue;  // LCOV_EXCL_LINE

        auto const zb = ab + *e * balance;
        auto const zrho = arho + *e * balanceBlinding;
        auto const zsk = ask + *e * secretKey;
        if (!allNonZero({zb, zrho, zsk}))
            continue;  // LCOV_EXCL_LINE
        return serialize({*e, zb, zrho, zsk});
    }
    proverFailed();  // LCOV_EXCL_LINE
}

bool
verifyBalance(BalanceStatement const& statement, Slice proof, uint256 const& contextID)
{
    auto const scalars = parseScalars(proof, 4);
    if (!scalars)
        return false;
    auto const& e = (*scalars)[0];
    auto const& zb = (*scalars)[1];
    auto const& zrho = (*scalars)[2];
    auto const& zsk = (*scalars)[3];

    // Equations (56)-(58).
    Challenge c("CMPT_CONVERTBACK_SIGMA");
    addBalanceStatement(c, statement);
    c.add(mulGenerator(zsk) - e * statement.key);
    c.add(mulGenerator(zb) + zsk * statement.balance.c1 - e * statement.balance.c2);
    c.add(mulGenerator(zb) + zrho * pedersenGenerator() - e * statement.balanceCommitment);
    auto const expected = c.add(contextID).finish();
    return expected && constantTimeEqual(*expected, e);
}

Buffer
proveClawback(
    Point const& issuerKey,
    ElGamalCiphertext const& mirror,
    Scalar const& amount,
    Scalar const& issuerSecretKey,
    uint256 const& contextID)
{
    auto const mG = mulGenerator(amount);
    require(
        encodable(issuerKey) && encodable(mirror.c1) && encodable(mirror.c2) && encodable(mG),
        "statement point is the identity");

    // The issuer key is the witness for every holder and the context omits
    // the mirror, so the nonce seed also binds the mirror: re-proving after it
    // changes must not reuse a nonce even if the RNG repeats.
    auto const c1 = *mirror.c1.bytes();
    auto const c2 = *mirror.c2.bytes();
    auto const statement = sha256(
        {Slice(c1.data(), c1.size()),
         Slice(c2.data(), c2.size()),
         Slice(contextID.data(), contextID.size())});
    HedgedNonces nonces(
        "CMPT_CLAWBACK_SIGMA", {issuerSecretKey, amount}, uint256::fromVoid(statement.data()));
    for (int attempt = 0; attempt < kMaxProverAttempts; ++attempt)
    {
        auto const a = nonces.next();
        auto const e = Challenge("CMPT_CLAWBACK_SIGMA")
                           .add(issuerKey)
                           .add(mirror.c1)
                           .add(mirror.c2)
                           .add(mG)
                           .add(mulGenerator(a))
                           .add(mulSecret(a, mirror.c1))
                           .add(contextID)
                           .finish();
        if (!e)
            continue;  // LCOV_EXCL_LINE
        auto const z = a + *e * issuerSecretKey;
        if (z.isZero())
            continue;  // LCOV_EXCL_LINE
        return serialize({*e, z});
    }
    proverFailed();  // LCOV_EXCL_LINE
}

bool
verifyClawback(
    Point const& issuerKey,
    ElGamalCiphertext const& mirror,
    Scalar const& amount,
    Slice proof,
    uint256 const& contextID)
{
    auto const scalars = parseScalars(proof, 2);
    if (!scalars)
        return false;
    auto const& e = (*scalars)[0];
    auto const& z = (*scalars)[1];
    auto const mG = mulGenerator(amount);

    // Equations (75)-(76).
    auto const expected = Challenge("CMPT_CLAWBACK_SIGMA")
                              .add(issuerKey)
                              .add(mirror.c1)
                              .add(mirror.c2)
                              .add(mG)
                              .add(mulGenerator(z) - e * issuerKey)
                              .add(z * mirror.c1 - e * (mirror.c2 - mG))
                              .add(contextID)
                              .finish();
    return expected && constantTimeEqual(*expected, e);
}

}  // namespace xrpl::confidential
