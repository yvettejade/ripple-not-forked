#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/crypto/Secp256k1.h>

#include <array>
#include <cstdint>
#include <optional>

namespace xrpl {

/** EC-ElGamal ciphertext over secp256k1: two compressed points (66 bytes).

    Encoding: C1 || C2 where
      C1 = r * G
      C2 = m * G + r * Y
    for plaintext amount m (uint64), public key Y, and randomness r.
*/
class ElGamalCiphertext
{
public:
    static constexpr std::size_t kSerializedSize =
        Secp256k1Point::kSerializedSize + Secp256k1Point::kSerializedSize;

private:
    Secp256k1Point c1_;
    Secp256k1Point c2_;

    ElGamalCiphertext(Secp256k1Point const& c1, Secp256k1Point const& c2);

public:
    ElGamalCiphertext() = delete;

    /** Parse a 66-byte encoding (two concatenated compressed points). */
    [[nodiscard]] static std::optional<ElGamalCiphertext>
    parse(Slice data);

    /** Encrypt a uint64 plaintext under publicKey with caller-provided randomness.

        Amount zero is supported (C2 = r * Y). Returns nullopt only if a group
        operation yields the point at infinity (astronomically rare for honest
        inputs) or if public-key/randomness objects are somehow unusable.
    */
    [[nodiscard]] static std::optional<ElGamalCiphertext>
    encrypt(
        std::uint64_t plaintext,
        Secp256k1Point const& publicKey,
        Secp256k1Scalar const& randomness);

    /** Homomorphic addition; nullopt if either component sums to infinity. */
    [[nodiscard]] std::optional<ElGamalCiphertext>
    add(ElGamalCiphertext const& other) const;

    /** Homomorphic subtraction; nullopt if either component difference is infinity. */
    [[nodiscard]] std::optional<ElGamalCiphertext>
    subtract(ElGamalCiphertext const& other) const;

    void
    serialize(void* dest) const;

    [[nodiscard]] std::array<std::uint8_t, kSerializedSize>
    serialize() const;

    [[nodiscard]] Secp256k1Point const&
    c1() const noexcept
    {
        return c1_;
    }

    [[nodiscard]] Secp256k1Point const&
    c2() const noexcept
    {
        return c2_;
    }

    [[nodiscard]] bool
    operator==(ElGamalCiphertext const& other) const noexcept
    {
        return c1_ == other.c1_ && c2_ == other.c2_;
    }
};

}  // namespace xrpl
