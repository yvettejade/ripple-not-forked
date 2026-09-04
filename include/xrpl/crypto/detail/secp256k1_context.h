#pragma once

#include <secp256k1.h>

namespace xrpl {
namespace detail {

/** Shared libsecp256k1 context for crypto-module group operations.

    Placed in the crypto module so levelization stays intact: protocol
    already depends on crypto, so crypto cannot include
    xrpl/protocol/detail/secp256k1.h.
*/
template <class = void>
secp256k1_context const*
secp256k1Context()
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
    static Holder const kH;
    return kH.impl;
}

}  // namespace detail
}  // namespace xrpl
