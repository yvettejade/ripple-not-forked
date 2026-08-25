#[===================================================================[
  mpt-crypto 1.0.5 (XRPLF/mpt-crypto@3baaaac) for confidential proof tests.
  Built from sources under external/mpt-crypto — not add_subdirectory, because
  that project also defines an INTERFACE target named `common`.
#]===================================================================]

set(MPT_CRYPTO_ROOT "${CMAKE_SOURCE_DIR}/external/mpt-crypto")

add_library(mpt-crypto STATIC)
target_sources(
    mpt-crypto
    PRIVATE
        "${MPT_CRYPTO_ROOT}/src/bulletproof_aggregated.c"
        "${MPT_CRYPTO_ROOT}/src/commitments.c"
        "${MPT_CRYPTO_ROOT}/src/elgamal.c"
        "${MPT_CRYPTO_ROOT}/src/bsgs_dlp.c"
        "${MPT_CRYPTO_ROOT}/src/mpt_scalar.c"
        "${MPT_CRYPTO_ROOT}/src/proof_pok_sk.c"
        "${MPT_CRYPTO_ROOT}/src/proof_compact_standard.c"
        "${MPT_CRYPTO_ROOT}/src/proof_compact_clawback.c"
        "${MPT_CRYPTO_ROOT}/src/proof_compact_convertback.c"
        "${MPT_CRYPTO_ROOT}/src/utility/mpt_utility.cpp"
)
target_include_directories(
    mpt-crypto
    PUBLIC "${MPT_CRYPTO_ROOT}/include"
    PRIVATE "${MPT_CRYPTO_ROOT}/src"
)
target_link_libraries(mpt-crypto PUBLIC secp256k1::secp256k1 OpenSSL::Crypto)
target_compile_definitions(mpt-crypto PRIVATE SECP256K1_WIDEMUL_INT128)
# Parent -Werror is too strict for this third-party C codebase.
target_compile_options(mpt-crypto PRIVATE -Wno-error)

function(add_mpt_crypto_test test_name source)
    add_executable(${test_name} "${MPT_CRYPTO_ROOT}/tests/${source}")
    target_include_directories(
        ${test_name}
        PRIVATE "${MPT_CRYPTO_ROOT}/tests" "${MPT_CRYPTO_ROOT}/include"
    )
    target_link_libraries(
        ${test_name}
        PRIVATE mpt-crypto secp256k1::secp256k1 OpenSSL::Crypto
    )
    target_compile_options(${test_name} PRIVATE -Wno-error)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

add_mpt_crypto_test(test_elgamal test_elgamal.c)
add_mpt_crypto_test(test_elgamal_verify test_elgamal_verify.c)
add_mpt_crypto_test(test_pok_sk test_pok_sk.c)
add_mpt_crypto_test(test_commitments test_commitments.c)
add_mpt_crypto_test(test_ipa test_ipa.c)
add_mpt_crypto_test(test_bulletproof_agg test_bulletproof_agg.c)
add_mpt_crypto_test(test_mpt_utility test_mpt_utility.cpp)
add_mpt_crypto_test(test_compact_standard test_compact_standard.c)
add_mpt_crypto_test(test_compact_clawback test_compact_clawback.c)
add_mpt_crypto_test(test_compact_convertback test_compact_convertback.c)
add_mpt_crypto_test(test_ct_tweak_mul test_ct_tweak_mul.c)
add_mpt_crypto_test(test_bsgs_dlp test_bsgs_dlp.c)
