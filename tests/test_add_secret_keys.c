//
// Created by Peter Paravinja on 25. 7. 25.
//
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "src/add_secret_keys.h"
#include "src/nist256_key_material.h"
#include "core.h"

// Helper function to print hex bytes
void print_hex_ask(const char* label, const unsigned char* data, int len)
{
    printf("   %s: ", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if (i < len - 1 && (i + 1) % 16 == 0)
            printf("\n        ");
        else if (i < len - 1 && (i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n");
}

// Helper function to compare two byte arrays
int bytes_equal_ask(const unsigned char* a, const unsigned char* b, int len)
{
    return memcmp(a, b, len) == 0;
}

// Helper function to check if byte array is all zeros
int is_all_zeros_ask(const unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}

// Generate some random seed data
void generate_random_seed_ask(unsigned char* seed, int len)
{
    // Simple pseudo-random for testing (not cryptographically secure for production)
    static int seeded = 0;
    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    for (int i = 0; i < len; i++)
    {
        seed[i] = (unsigned char)(rand() & 0xFF);
    }
}

// Helper function to generate a valid NIST P-256 private key from seed
int generate_valid_private_key(unsigned char* key_bytes, unsigned char* seed, int seed_len)
{
    // Generate private key from seed
    BIG_256_56 private_key;
    if (nist256_generate_secret_key(private_key, seed, seed_len) != 0)
    {
        return -1;
    }

    // Convert to bytes
    BIG_256_56_toBytes((char*)key_bytes, private_key);
    return 0;
}

int main()
{
    printf("=== Add Secret Keys Test ===\n\n");

    // Test 1: Basic secret key addition
    printf("1. Testing basic secret key addition...\n");

    // Generate two valid private keys
    unsigned char seed1[32], seed2[32];
    unsigned char key1[32], key2[32];
    generate_random_seed_ask(seed1, 32);
    generate_random_seed_ask(seed2, 32);

    // Ensure seeds are different
    seed2[0] = ~seed1[0];
    seed2[1] = ~seed1[1];

    if (generate_valid_private_key(key1, seed1, 32) != 0)
    {
        printf("   ❌ FAILED to generate test key 1\n");
        return 1;
    }
    if (generate_valid_private_key(key2, seed2, 32) != 0)
    {
        printf("   ❌ FAILED to generate test key 2\n");
        return 1;
    }

    nist256_key_material_t result_key;
    const int test1_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, &result_key);

    printf("   Result code: %d\n", test1_result);
    printf("   Expected: %d (CVC_ADD_SECRET_KEYS_SUCCESS)\n", CVC_ADD_SECRET_KEYS_SUCCESS);
    int test1_success = (test1_result == CVC_ADD_SECRET_KEYS_SUCCESS);
    printf("   Status: %s\n", test1_success ? "✅ PASSED" : "❌ FAILED");

    if (test1_success)
    {
        // Check that result components are non-zero
        const int private_nonzero = !is_all_zeros_ask(result_key.private_key_bytes, 32);
        const int public_x_nonzero = !is_all_zeros_ask(result_key.public_key_x_bytes, 32);
        const int public_y_nonzero = !is_all_zeros_ask(result_key.public_key_y_bytes, 32);

        printf("   Result private key is non-zero: %s\n", private_nonzero ? "✅ YES" : "❌ NO");
        printf("   Result public key X is non-zero: %s\n", public_x_nonzero ? "✅ YES" : "❌ NO");
        printf("   Result public key Y is non-zero: %s\n", public_y_nonzero ? "✅ YES" : "❌ NO");

        test1_success = private_nonzero && public_x_nonzero && public_y_nonzero;

        // Verify result is different from both input keys
        const int different_from_key1 = !bytes_equal_ask(result_key.private_key_bytes, key1, 32);
        const int different_from_key2 = !bytes_equal_ask(result_key.private_key_bytes, key2, 32);

        printf("   Result different from key1: %s\n", different_from_key1 ? "✅ YES" : "❌ NO");
        printf("   Result different from key2: %s\n", different_from_key2 ? "✅ YES" : "❌ NO");

        test1_success = test1_success && different_from_key1 && different_from_key2;

        // Display sample of result key material
        print_hex_ask("Result private key (first 16 bytes)", result_key.private_key_bytes, 16);
        print_hex_ask("Result public key X (first 16 bytes)", result_key.public_key_x_bytes, 16);
    }
    printf("\n");

    // Test 2: Invalid parameters - NULL pointers
    printf("2. Testing invalid parameters (NULL pointers)...\n");

    nist256_key_material_t dummy_result;

    // Test 2a: NULL first key
    const int test2a_result = cvc_add_nist256_secret_keys(NULL, 32, key2, 32, &dummy_result);
    printf("   NULL first key result: %d\n", test2a_result);

    // Test 2b: NULL second key
    const int test2b_result = cvc_add_nist256_secret_keys(key1, 32, NULL, 32, &dummy_result);
    printf("   NULL second key result: %d\n", test2b_result);

    // Test 2c: NULL result pointer
    const int test2c_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, NULL);
    printf("   NULL result pointer result: %d\n", test2c_result);

    const int test2_success = (test2a_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS) && (test2b_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS) && (test2c_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS);

    printf("   Expected: %d (CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS)\n", CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS);
    printf("   Status: %s\n\n", test2_success ? "✅ PASSED" : "❌ FAILED");

    // Test 3: Invalid parameters - wrong key lengths
    printf("3. Testing invalid parameters (wrong key lengths)...\n");

    // Test 3a: First key too short
    const int test3a_result = cvc_add_nist256_secret_keys(key1, 16, key2, 32, &dummy_result);
    printf("   First key too short result: %d\n", test3a_result);

    // Test 3b: Second key too short
    const int test3b_result = cvc_add_nist256_secret_keys(key1, 32, key2, 24, &dummy_result);
    printf("   Second key too short result: %d\n", test3b_result);

    // Test 3c: Both keys wrong length
    const int test3c_result = cvc_add_nist256_secret_keys(key1, 31, key2, 33, &dummy_result);
    printf("   Both keys wrong length result: %d\n", test3c_result);

    const int test3_success = (test3a_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS) && (test3b_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS) && (test3c_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS);

    printf("   Expected: %d (CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS)\n", CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS);
    printf("   Status: %s\n\n", test3_success ? "✅ PASSED" : "❌ FAILED");

    // Test 4: Invalid key values - zero keys
    printf("4. Testing invalid key values (zero keys)...\n");

    unsigned char zero_key[32] = { 0 }; // All zeros - invalid private key

    // Test 4a: First key is zero
    const int test4a_result = cvc_add_nist256_secret_keys(zero_key, 32, key2, 32, &dummy_result);
    printf("   First key zero result: %d\n", test4a_result);

    // Test 4b: Second key is zero
    const int test4b_result = cvc_add_nist256_secret_keys(key1, 32, zero_key, 32, &dummy_result);
    printf("   Second key zero result: %d\n", test4b_result);

    // Test 4c: Both keys are zero
    const int test4c_result = cvc_add_nist256_secret_keys(zero_key, 32, zero_key, 32, &dummy_result);
    printf("   Both keys zero result: %d\n", test4c_result);

    const int test4_success = (test4a_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1) && (test4b_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY2) && (test4c_result == CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1); // First error detected

    printf("   Expected various invalid key errors\n");
    printf("   Status: %s\n\n", test4_success ? "✅ PASSED" : "❌ FAILED");

    // Test 5: Deterministic behavior
    printf("5. Testing deterministic behavior...\n");

    nist256_key_material_t result_a, result_b;

    // Same inputs should produce same outputs
    const int test5a_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, &result_a);
    const int test5b_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, &result_b);

    printf("   First addition result: %d\n", test5a_result);
    printf("   Second addition result: %d\n", test5b_result);

    int test5_success = (test5a_result == CVC_ADD_SECRET_KEYS_SUCCESS) && (test5b_result == CVC_ADD_SECRET_KEYS_SUCCESS);

    if (test5_success)
    {
        const int private_equal = bytes_equal_ask(result_a.private_key_bytes, result_b.private_key_bytes, 32);
        const int public_x_equal = bytes_equal_ask(result_a.public_key_x_bytes, result_b.public_key_x_bytes, 32);
        const int public_y_equal = bytes_equal_ask(result_a.public_key_y_bytes, result_b.public_key_y_bytes, 32);

        printf("   Private keys are identical: %s\n", private_equal ? "✅ YES" : "❌ NO");
        printf("   Public X coords are identical: %s\n", public_x_equal ? "✅ YES" : "❌ NO");
        printf("   Public Y coords are identical: %s\n", public_y_equal ? "✅ YES" : "❌ NO");

        test5_success = private_equal && public_x_equal && public_y_equal;
    }
    printf("   Status: %s\n\n", test5_success ? "✅ PASSED" : "❌ FAILED");

    // Test 6: Commutative property (A + B = B + A)
    printf("6. Testing commutative property (A + B = B + A)...\n");

    nist256_key_material_t result_ab, result_ba;

    const int test6a_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, &result_ab);
    const int test6b_result = cvc_add_nist256_secret_keys(key2, 32, key1, 32, &result_ba);

    printf("   A + B result: %d\n", test6a_result);
    printf("   B + A result: %d\n", test6b_result);

    int test6_success = (test6a_result == CVC_ADD_SECRET_KEYS_SUCCESS) && (test6b_result == CVC_ADD_SECRET_KEYS_SUCCESS);

    if (test6_success)
    {
        const int private_equal = bytes_equal_ask(result_ab.private_key_bytes, result_ba.private_key_bytes, 32);
        const int public_x_equal = bytes_equal_ask(result_ab.public_key_x_bytes, result_ba.public_key_x_bytes, 32);
        const int public_y_equal = bytes_equal_ask(result_ab.public_key_y_bytes, result_ba.public_key_y_bytes, 32);

        printf("   A + B = B + A (private): %s\n", private_equal ? "✅ YES" : "❌ NO");
        printf("   A + B = B + A (public X): %s\n", public_x_equal ? "✅ YES" : "❌ NO");
        printf("   A + B = B + A (public Y): %s\n", public_y_equal ? "✅ YES" : "❌ NO");

        test6_success = private_equal && public_x_equal && public_y_equal;
    }
    printf("   Status: %s\n\n", test6_success ? "✅ PASSED" : "❌ FAILED");

    // Test 7: Adding same key to itself (A + A = 2A)
    printf("7. Testing self-addition (A + A)...\n");

    nist256_key_material_t result_aa;
    const int test7_result = cvc_add_nist256_secret_keys(key1, 32, key1, 32, &result_aa);

    printf("   A + A result: %d\n", test7_result);
    int test7_success = (test7_result == CVC_ADD_SECRET_KEYS_SUCCESS);

    if (test7_success)
    {
        // Verify result is different from original key
        const int different_from_original = !bytes_equal_ask(result_aa.private_key_bytes, key1, 32);
        printf("   A + A different from A: %s\n", different_from_original ? "✅ YES" : "❌ NO");

        // Check that result components are non-zero
        const int private_nonzero = !is_all_zeros_ask(result_aa.private_key_bytes, 32);
        const int public_x_nonzero = !is_all_zeros_ask(result_aa.public_key_x_bytes, 32);
        const int public_y_nonzero = !is_all_zeros_ask(result_aa.public_key_y_bytes, 32);

        printf("   A + A private is non-zero: %s\n", private_nonzero ? "✅ YES" : "❌ NO");
        printf("   A + A public X is non-zero: %s\n", public_x_nonzero ? "✅ YES" : "❌ NO");
        printf("   A + A public Y is non-zero: %s\n", public_y_nonzero ? "✅ YES" : "❌ NO");

        test7_success = different_from_original && private_nonzero && public_x_nonzero && public_y_nonzero;
    }
    printf("   Status: %s\n\n", test7_success ? "✅ PASSED" : "❌ FAILED");

    // Test 8: Different key pairs produce different results
    printf("8. Testing different key pairs produce different results...\n");

    // Generate a third key
    unsigned char seed3[32], key3[32];
    generate_random_seed_ask(seed3, 32);
    seed3[0] = ~seed1[0];
    seed3[1] = ~seed2[1];
    seed3[2] = seed1[2] ^ seed2[2];

    if (generate_valid_private_key(key3, seed3, 32) != 0)
    {
        printf("   ❌ FAILED to generate test key 3\n");
        return 1;
    }

    nist256_key_material_t result_12, result_13;
    const int test8a_result = cvc_add_nist256_secret_keys(key1, 32, key2, 32, &result_12);
    const int test8b_result = cvc_add_nist256_secret_keys(key1, 32, key3, 32, &result_13);

    printf("   Key1 + Key2 result: %d\n", test8a_result);
    printf("   Key1 + Key3 result: %d\n", test8b_result);

    int test8_success = (test8a_result == CVC_ADD_SECRET_KEYS_SUCCESS) && (test8b_result == CVC_ADD_SECRET_KEYS_SUCCESS);

    if (test8_success)
    {
        const int private_different = !bytes_equal_ask(result_12.private_key_bytes, result_13.private_key_bytes, 32);
        const int public_x_different = !bytes_equal_ask(result_12.public_key_x_bytes, result_13.public_key_x_bytes, 32);
        const int public_y_different = !bytes_equal_ask(result_12.public_key_y_bytes, result_13.public_key_y_bytes, 32);

        printf("   Different key pairs give different private: %s\n", private_different ? "✅ YES" : "❌ NO");
        printf("   Different key pairs give different public X: %s\n", public_x_different ? "✅ YES" : "❌ NO");
        printf("   Different key pairs give different public Y: %s\n", public_y_different ? "✅ YES" : "❌ NO");

        test8_success = private_different && public_x_different && public_y_different;
    }
    printf("   Status: %s\n\n", test8_success ? "✅ PASSED" : "❌ FAILED");

    // Summary
    printf("=== Add Secret Keys Test Summary ===\n");
    const int all_tests_passed = test1_success && test2_success && test3_success && test4_success && test5_success && test6_success && test7_success && test8_success;

    if (all_tests_passed)
    {
        printf("🎉 All add secret keys tests PASSED! The function is working correctly.\n");
        printf("✅ Basic secret key addition: PASSED\n");
        printf("✅ NULL pointer parameter validation: PASSED\n");
        printf("✅ Key length parameter validation: PASSED\n");
        printf("✅ Invalid key value handling: PASSED\n");
        printf("✅ Deterministic behavior: PASSED\n");
        printf("✅ Commutative property: PASSED\n");
        printf("✅ Self-addition: PASSED\n");
        printf("✅ Different inputs produce different outputs: PASSED\n");
        return 0;
    }
    else
    {
        printf("💥 Some add secret keys tests FAILED! Check the output above for details.\n");
        printf("%s Basic secret key addition: %s\n", test1_success ? "✅" : "❌", test1_success ? "PASSED" : "FAILED");
        printf("%s NULL pointer parameter validation: %s\n", test2_success ? "✅" : "❌", test2_success ? "PASSED" : "FAILED");
        printf("%s Key length parameter validation: %s\n", test3_success ? "✅" : "❌", test3_success ? "PASSED" : "FAILED");
        printf("%s Invalid key value handling: %s\n", test4_success ? "✅" : "❌", test4_success ? "PASSED" : "FAILED");
        printf("%s Deterministic behavior: %s\n", test5_success ? "✅" : "❌", test5_success ? "PASSED" : "FAILED");
        printf("%s Commutative property: %s\n", test6_success ? "✅" : "❌", test6_success ? "PASSED" : "FAILED");
        printf("%s Self-addition: %s\n", test7_success ? "✅" : "❌", test7_success ? "PASSED" : "FAILED");
        printf("%s Different inputs produce different outputs: %s\n", test8_success ? "✅" : "❌", test8_success ? "PASSED" : "FAILED");
        return 1;
    }
}
