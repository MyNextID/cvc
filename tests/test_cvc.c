//
// Created by Peter Paravinja on 14. 7. 25.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "src/crypto.h"
#include "src/nist256_key_material.h"

// Helper function to print hex bytes
void print_hex(const char* label, const unsigned char* data, int len)
{
    printf("   %s: ", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if (i < len - 1 && (i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n");
}

// Helper function to compare two byte arrays
int bytes_equal(const unsigned char* a, const unsigned char* b, int len)
{
    return memcmp(a, b, len) == 0;
}

// Helper function to check if byte array is all zeros
int is_all_zeros(const unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}

// Generate some random seed data
void generate_random_seed(unsigned char* seed, int len)
{
    // Simple pseudo-random for testing (not cryptographically secure)
    srand((unsigned int)time(NULL));
    for (int i = 0; i < len; i++)
    {
        seed[i] = (unsigned char)(rand() & 0xFF);
    }
}

int main()
{
    printf("=== CVC Library Test ===\n\n");

    // Test 1: Basic library call
    printf("1. Testing basic library function...\n");
    const char* hello_result = cvc_hello_world();
    printf("   Result: %s\n", hello_result);
    printf("   Status: %s\n\n", hello_result != NULL ? "✅ PASSED" : "❌ FAILED");

    // Test 2: MIRACL integration test
    printf("2. Testing MIRACL integration...\n");
    int miracl_result = cvc_test_miracl_big_add();
    printf("   Result: %d\n", miracl_result);
    printf("   Status: %s\n\n", miracl_result == 1 ? "✅ PASSED" : "❌ FAILED");

    // Test 3: NIST256 secret key generation
    printf("3. Testing NIST256 secret key generation...\n");

    // Test 3a: Valid key generation
    unsigned char seed1[32];
    generate_random_seed(seed1, 32);

    BIG_256_56 secret_key1;
    int result1 = nist256_generate_secret_key(secret_key1, seed1, 32);
    printf("   Key generation result: %d\n", result1);

    // Check if key is non-zero
    int key1_nonzero = !BIG_256_56_iszilch(secret_key1);
    printf("   Key is non-zero: %s\n", key1_nonzero ? "✅ YES" : "❌ NO");

    // Test 3b: Generate second key with different seed
    unsigned char seed2[32];
    generate_random_seed(seed2, 32);
    // Make sure seed2 is different from seed1
    seed2[0] = ~seed1[0];
    seed2[1] = ~seed1[1];

    BIG_256_56 secret_key2;
    int result2 = nist256_generate_secret_key(secret_key2, seed2, 32);
    printf("   Second key generation result: %d\n", result2);

    // Check if second key is different from first
    int keys_different = BIG_256_56_comp(secret_key1, secret_key2) != 0;
    printf("   Keys are different: %s\n", keys_different ? "✅ YES" : "❌ NO");

    // Test 3c: Invalid parameters
    BIG_256_56 invalid_key;
    int invalid_result1 = nist256_generate_secret_key(invalid_key, NULL, 32);
    int invalid_result2 = nist256_generate_secret_key(invalid_key, seed1, 8); // Too short
    printf("   NULL seed error handling: %s\n", invalid_result1 < 0 ? "✅ PASSED" : "❌ FAILED");
    printf("   Short seed error handling: %s\n", invalid_result2 < 0 ? "✅ PASSED" : "❌ FAILED");

    printf("   Status: %s\n\n", (result1 == 0 && result2 == 0 && key1_nonzero && keys_different && invalid_result1 < 0 && invalid_result2 < 0) ? "✅ PASSED" : "❌ FAILED");

    // Test 4: NIST256 key material extraction
    printf("4. Testing NIST256 key material extraction...\n");

    // Test 4a: Extract key material from first generated key
    printf("   Step 1: Initializing key_material structure...\n");
    nist256_key_material_t key_material1;
    memset(&key_material1, 0, sizeof(key_material1));

    printf("   Step 2: Calling nist256_big_to_key_material...\n");
    fflush(stdout); // Force output before potential crash

    int extract_result1 = nist256_big_to_key_material(secret_key1, &key_material1);

    printf("   Step 3: Function returned successfully\n");
    printf("   Key material extraction result: %d\n", extract_result1);

    // Check if extracted private key matches original
    unsigned char original_key_bytes[MODBYTES_256_56];
    BIG_256_56_toBytes((char*)original_key_bytes, secret_key1);
    int private_key_matches = bytes_equal(key_material1.private_key_bytes, original_key_bytes, MODBYTES_256_56);
    printf("   Private key bytes match: %s\n", private_key_matches ? "✅ YES" : "❌ NO");

    // Check if public key coordinates are non-zero
    int pubkey_x_nonzero = !is_all_zeros(key_material1.public_key_x_bytes, MODBYTES_256_56);
    int pubkey_y_nonzero = !is_all_zeros(key_material1.public_key_y_bytes, MODBYTES_256_56);
    printf("   Public key X is non-zero: %s\n", pubkey_x_nonzero ? "✅ YES" : "❌ NO");
    printf("   Public key Y is non-zero: %s\n", pubkey_y_nonzero ? "✅ YES" : "❌ NO");

    // Test 4b: Extract key material from second key
    nist256_key_material_t key_material2;
    int extract_result2 = nist256_big_to_key_material(secret_key2, &key_material2);

    // Check if the two key materials are different
    int private_keys_different = !bytes_equal(key_material1.private_key_bytes, key_material2.private_key_bytes, MODBYTES_256_56);
    int public_x_different = !bytes_equal(key_material1.public_key_x_bytes, key_material2.public_key_x_bytes, MODBYTES_256_56);
    int public_y_different = !bytes_equal(key_material1.public_key_y_bytes, key_material2.public_key_y_bytes, MODBYTES_256_56);

    printf("   Private key materials different: %s\n", private_keys_different ? "✅ YES" : "❌ NO");
    printf("   Public key X coordinates different: %s\n", public_x_different ? "✅ YES" : "❌ NO");
    printf("   Public key Y coordinates different: %s\n", public_y_different ? "✅ YES" : "❌ NO");

    // Test 4c: Invalid parameters
    int invalid_extract = nist256_big_to_key_material(secret_key1, NULL);
    printf("   NULL pointer error handling: %s\n", invalid_extract < 0 ? "✅ PASSED" : "❌ FAILED");

    printf("   Status: %s\n\n",
        (extract_result1 == 0 && extract_result2 == 0 && private_key_matches && pubkey_x_nonzero && pubkey_y_nonzero && private_keys_different && public_x_different && public_y_different && invalid_extract < 0) ? "✅ PASSED" : "❌ FAILED");

    // Test 5: Display sample key material (first 16 bytes of each component)
    printf("5. Sample key material display...\n");
    print_hex("Private Key (first 16 bytes)", key_material1.private_key_bytes, 16);
    print_hex("Public Key X (first 16 bytes)", key_material1.public_key_x_bytes, 16);
    print_hex("Public Key Y (first 16 bytes)", key_material1.public_key_y_bytes, 16);
    printf("   Status: ✅ DISPLAYED\n\n");

    // Summary
    printf("=== Test Summary ===\n");
    if (hello_result != NULL && miracl_result == 1 && extract_result1 == 0 && extract_result2 == 0 && private_key_matches && keys_different)
    {
        printf("🎉 All tests PASSED! CVC library with NIST256 key material is working correctly.\n");
        return 0;
    }
    else
    {
        printf("💥 Some tests FAILED! Check the output above for details.\n");
        return 1;
    }
}