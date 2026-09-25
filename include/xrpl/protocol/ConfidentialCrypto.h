#pragma once

#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/UintTypes.h>

#include <secp256k1.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

/** secp256k1 group primitives and EC-ElGamal encryption for XLS-0096
    Confidential MPTs.

    Validators only verify public data (ciphertexts, keys, commitments and
    disclosed blinding factors), for which the variable-time operations are
    appropriate. Code that handles secret scalars (provers, decryption) must
    use mulGenerator and mulSecret, whose multiplication is constant-time in
    the scalar, zero included. mulSecret then re-parses the product with
    libsecp256k1's variable-time point validation, whose work depends only on
    the point being valid (it always is). Scalar arithmetic never branches on
    a value, and Scalar and Point storage is wiped on destruction.

    Point addition is variable-time and short-circuits the identity, so a
    prover must not add a product whose scalar may be a secret zero (a bit,
    an empty balance) without masking it first; pedersenCommit and
    elGamalEncrypt do this for their message, and the Bulletproof prover
    rejects zero blinding factors.

    Every hash is SHA-256, and hash outputs become scalars by reduction mod n.
*/
namespace xrpl::confidential {

/** Length of a compressed secp256k1 point (the specification's ecPubKeyLength). */
inline constexpr std::size_t kEcPointLength = 33;

/** Length of a big-endian secp256k1 scalar. */
inline constexpr std::size_t kScalarLength = 32;

/** Length of a serialized EC-ElGamal ciphertext (C1 || C2). */
inline constexpr std::size_t kElGamalCiphertextLength = 2 * kEcPointLength;

/** An integer modulo the secp256k1 group order n. */
class Scalar
{
    std::array<std::uint8_t, kScalarLength> bytes_{};

public:
    /** The zero scalar. */
    Scalar() = default;

    Scalar(Scalar const&) = default;

    Scalar&
    operator=(Scalar const&) = default;

    /** Wipes the value; scalars may hold secrets. */
    ~Scalar();

    /** Parse a canonical 32-byte big-endian scalar.

        @return the scalar, or nullopt unless the input is exactly 32 bytes
                encoding a value less than n.
    */
    [[nodiscard]] static std::optional<Scalar>
    fromBytes(Slice s);

    [[nodiscard]] static Scalar
    fromUint64(std::uint64_t v);

    /** A 32-byte big-endian digest reduced modulo n. */
    [[nodiscard]] static Scalar
    fromDigest(std::array<std::uint8_t, kScalarLength> const& digest);

    /** A uniformly random non-zero scalar from the system CSPRNG.

        @throws std::runtime_error if the CSPRNG keeps returning invalid
                scalars, which only a broken generator does.
    */
    [[nodiscard]] static Scalar
    random();

    [[nodiscard]] bool
    isZero() const;

    /** The multiplicative inverse.

        @throws std::domain_error if this scalar is zero.
    */
    [[nodiscard]] Scalar
    inverse() const;

    friend Scalar
    operator+(Scalar const& a, Scalar const& b);

    friend Scalar
    operator-(Scalar const& a);

    friend Scalar
    operator-(Scalar const& a, Scalar const& b);

    friend Scalar
    operator*(Scalar const& a, Scalar const& b);

    /** Big-endian encoding. */
    [[nodiscard]] std::array<std::uint8_t, kScalarLength> const&
    bytes() const
    {
        return bytes_;
    }

    friend bool
    operator==(Scalar const&, Scalar const&) = default;
};

/** A secp256k1 group element, including the point at infinity. */
class Point
{
    secp256k1_pubkey pk_{};
    bool infinity_ = true;

public:
    /** The point at infinity (the group identity). */
    Point() = default;

    Point(Point const&) = default;

    Point&
    operator=(Point const&) = default;

    /** Wipes the value; products of secret scalars, such as m·G for a small
        amount m, reveal the secret.
    */
    ~Point();

    /** The standard secp256k1 base point G. */
    [[nodiscard]] static Point
    generator();

    /** Parse a 33-byte compressed point.

        @return the point, or nullopt unless the input is exactly 33 bytes
                with a 0x02/0x03 prefix and an x coordinate on the curve.
                The point at infinity has no such encoding.
    */
    [[nodiscard]] static std::optional<Point>
    fromBytes(Slice s);

    /** Compressed encoding, or nullopt for the point at infinity. */
    [[nodiscard]] std::optional<std::array<std::uint8_t, kEcPointLength>>
    bytes() const;

    [[nodiscard]] bool
    isInfinity() const
    {
        return infinity_;
    }

    friend Point
    operator+(Point const& a, Point const& b);

    friend Point
    operator-(Point const& a);

    friend Point
    operator-(Point const& a, Point const& b);

    /** Variable-time; only use with public scalars. */
    friend Point
    operator*(Scalar const& k, Point const& p);

    /** k·p in constant time, for secret k. */
    friend Point
    mulSecret(Scalar const& k, Point const& p);

    friend bool
    operator==(Point const& a, Point const& b);

    /** k·G */
    friend Point
    mulGenerator(Scalar const& k);

    friend Point
    multiScalarMul(std::span<Scalar const> scalars, std::span<Point const> points);

    friend Point
    sumPoints(std::span<Point const> points);
};

/** The sum of the points, computed in one pass. */
[[nodiscard]] Point
sumPoints(std::span<Point const> points);

/** Σ scalars[i]·points[i]; the empty sum is the point at infinity.

    @throws std::invalid_argument if the spans differ in length.
*/
[[nodiscard]] Point
multiScalarMul(std::span<Scalar const> scalars, std::span<Point const> points);

/** Hedged prover nonces: SHA-256(tag || secrets || context || entropy ||
    u32be(counter)) mod n with 32 bytes of fresh CSPRNG entropy, skipping
    zero. Nonces stay unique if either the RNG or the witness differs, and
    the seed is wiped on destruction.
*/
class HedgedNonces
{
    std::vector<std::uint8_t> seed_;
    std::uint32_t counter_ = 0;

public:
    HedgedNonces(
        std::string_view tag,
        std::initializer_list<Scalar> secrets,
        uint256 const& contextID);

    HedgedNonces(HedgedNonces const&) = delete;

    HedgedNonces&
    operator=(HedgedNonces const&) = delete;

    ~HedgedNonces();

    [[nodiscard]] Scalar
    next();
};

/** SHA-256 of the concatenation of the given byte strings. */
[[nodiscard]] std::array<std::uint8_t, kScalarLength>
sha256(std::initializer_list<Slice> parts);

/** Deterministic hash-to-curve by try-and-increment: for ctr = 0, 1, ... the
    first valid point with compressed encoding 02 || SHA-256(seed || u32be(ctr)).

    Seeds must be fixed-format, domain-separated tags: variable-length seeds
    could alias another seed's counter bytes.
*/
[[nodiscard]] Point
hashToCurve(Slice seed);

/** True if no point is the identity and no two points share an x
    coordinate, that is, none equals another or its negation.

    The generators below are checked with this on first use, together with
    G; a collision throws std::logic_error.
*/
[[nodiscard]] bool
distinctUpToSign(std::span<Point const> points);

/** Number of Bulletproof vector generators: 64 bits for 2 aggregated values. */
inline constexpr std::size_t kMaxBulletproofBits = 128;

/** The Pedersen blinding generator H = hashToCurve("CMPT_PEDERSEN_H"). */
[[nodiscard]] Point const&
pedersenGenerator();

/** The inner-product generator u = hashToCurve("CMPT_BP_U"). */
[[nodiscard]] Point const&
innerProductGenerator();

/** G_i = hashToCurve("CMPT_BP_G" || u32be(i)), i < kMaxBulletproofBits. */
[[nodiscard]] std::span<Point const>
bulletproofGeneratorsG();

/** H_i = hashToCurve("CMPT_BP_H" || u32be(i)), i < kMaxBulletproofBits. */
[[nodiscard]] std::span<Point const>
bulletproofGeneratorsH();

/** Pedersen commitment value·G + blinding·H; both products are
    constant-time multiplications.
*/
[[nodiscard]] Point
pedersenCommit(Scalar const& value, Scalar const& blinding);

[[nodiscard]] Point
mulGenerator(Scalar const& k);

[[nodiscard]] Point
mulSecret(Scalar const& k, Point const& p);

/** True if the input is a valid 33-byte compressed secp256k1 point. */
[[nodiscard]] bool
isValidPoint(Slice s);

/** An EC-ElGamal ciphertext (C1, C2) = (r·G, m·G + r·Pk).

    Homomorphic addition and subtraction of attacker-influenced ciphertexts
    can yield a component equal to the point at infinity, which has no
    encoding. Callers must check toBuffer() before storing a result.
*/
struct ElGamalCiphertext
{
    Point c1;
    Point c2;

    /** Parse C1 || C2; both halves must be valid compressed points. */
    [[nodiscard]] static std::optional<ElGamalCiphertext>
    fromBytes(Slice s);

    /** Serialize as C1 || C2, or nullopt if either half is the point at
        infinity and therefore has no encoding.
    */
    [[nodiscard]] std::optional<Buffer>
    toBuffer() const;

    friend ElGamalCiphertext
    operator+(ElGamalCiphertext const& a, ElGamalCiphertext const& b);

    friend ElGamalCiphertext
    operator-(ElGamalCiphertext const& a, ElGamalCiphertext const& b);

    friend bool
    operator==(ElGamalCiphertext const&, ElGamalCiphertext const&) = default;
};

/** Enc_pk(m; r) = (r·G, m·G + r·pk); every product is a constant-time
    multiplication.

    @throws std::invalid_argument if pk is the point at infinity.
*/
[[nodiscard]] ElGamalCiphertext
elGamalEncrypt(Scalar const& m, Scalar const& r, Point const& pk);

/** Randomness of the canonical encrypted zero (XLS-0096 §9.4):
    SHA-256("EncZero" || account || issuer || issuance) mod n, or 1 if that
    reduces to zero.
*/
[[nodiscard]] Scalar
encryptedZeroRandomness(AccountID const& account, MPTID const& issuance);

/** The canonical encrypted zero of an account's balance under pk. */
[[nodiscard]] ElGamalCiphertext
encryptedZero(AccountID const& account, MPTID const& issuance, Point const& pk);

/** TransactionContextID (Updated spec eq. 40, 61, 77):
    SHA-256(u16be(txType) || account || issuance || u32be(sequence) ||
            party || u32be(version)).

    The trailing party and version form TxSpecific: the destination and the
    sender's version for Send, the account and its version for ConvertBack,
    the holder and 0 for Clawback, and the account and 0 for Convert.
*/
[[nodiscard]] uint256
transactionContextID(
    std::uint16_t txType,
    AccountID const& account,
    MPTID const& issuance,
    std::uint32_t sequence,
    AccountID const& party,
    std::uint32_t version);

/** Deterministic plaintext-ciphertext check using a disclosed blinding
    factor: C1 == r·G and C2 == m·G + r·pk.

    Fails for a zero blinding factor and for any ciphertext or key component
    at infinity, none of which can appear in a valid serialized ciphertext.
*/
[[nodiscard]] bool
verifyElGamalEncryption(
    ElGamalCiphertext const& ct,
    Scalar const& m,
    Scalar const& r,
    Point const& pk);

}  // namespace xrpl::confidential
