#include <stdio.h>
#include <assert.h>
#include <string.h>

#pragma GCC diagnostic push
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wduplicated-branches"
#endif
#include <cpr/cpr.h>
#pragma GCC diagnostic pop

#include <secp256k1.h>

#include "../../src/ecdsa_util.h"
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_all.hpp>

unsigned int Factorial( unsigned int number ) {
    return number <= 1 ? number : Factorial(number-1)*number;
}

int add(int a, int b) { return a + b; }

int ecdsa() {
    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function was SHA-256.
     * An actual implementation should just call SHA-256, but this example
     * hardcodes the output to avoid depending on an additional library.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116 */
    unsigned char msg_hash[32] = {
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    };
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    size_t len;
    int is_signature_valid, is_signature_valid2;
    int return_val;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    /* Before we can call actual API functions, we need to create a "context". */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ethyl_fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/

    /* If the secret key is zero or out of range (bigger than secp256k1's
     * order), we try to sample a new key. Note that the probability of this
     * happening is negligible. */
    while (1) {
        if (!ethyl_fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    /* Public key creation using a valid context with a verified secret key should never fail */
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    /* Serialize the pubkey in a compressed form(33 bytes). Should always return 1. */
    len = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(compressed_pubkey));

    /*** Signing ***/

    /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
     * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
     * Signing with a valid context, verified secret key
     * and the default nonce function should never fail. */
    return_val = secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey, NULL, NULL);
    assert(return_val);

    /* Serialize the signature in a compact form. Should always return 1
     * according to the documentation in secp256k1.h. */
    return_val = secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
    assert(return_val);


    /*** Verification ***/

    /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
        printf("Failed parsing the signature\n");
        return 1;
    }

    /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, sizeof(compressed_pubkey))) {
        printf("Failed parsing the public key\n");
        return 1;
    }

    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    is_signature_valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);

    std::string seckey_hex = oxenc::to_hex(std::begin(seckey), std::end(seckey));
    std::string compressed_pubkey_hex = oxenc::to_hex(std::begin(compressed_pubkey), std::end(compressed_pubkey));
    std::string serialized_signature_hex = oxenc::to_hex(std::begin(serialized_signature), std::end(serialized_signature));

    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    printf("Secret Key: %s\n", seckey_hex.c_str());
    printf("Public Key: %s\n", compressed_pubkey_hex.c_str());
    printf("Signature: %s\n", serialized_signature_hex.c_str());

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* Bonus example: if all we need is signature verification (and no key
       generation or signing), we don't need to use a context created via
       secp256k1_context_create(). We can simply use the static (i.e., global)
       context secp256k1_context_static. See its description in
       include/secp256k1.h for details. */
    is_signature_valid2 = secp256k1_ecdsa_verify(secp256k1_context_static,
                                                 &sig, msg_hash, &pubkey);
    assert(is_signature_valid2 == is_signature_valid);

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), Or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * Here we are preventing these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    ethyl_secure_erase(seckey, sizeof(seckey));

    return 0;
}

TEST_CASE( "Factorials are computed", "[basic]" ) {
    REQUIRE( Factorial(1) == 1 );
    REQUIRE( Factorial(2) == 2 );
    REQUIRE( Factorial(3) == 6 );
    REQUIRE( Factorial(10) == 3628800 );
}

TEST_CASE( "Add", "[basic]" ) {
    REQUIRE( add(1,2) == 3 );
}

TEST_CASE( "ECDSA", "[basic]" ) {
    REQUIRE( ecdsa() == 0 );
}

