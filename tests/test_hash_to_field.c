//
// Created by Peter Paravinja on 21. 7. 25.
//
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "src/hash_to_field.h"
#include "src/nist256_key_material.h"
#include "core.h"

// Helper function to print hex bytes
void print_hex_htf(const char* label, const unsigned char* data, int len)
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
int bytes_equal_htf(const unsigned char* a, const unsigned char* b, int len)
{
    return memcmp(a, b, len) == 0;
}

// Helper function to check if byte array is all zeros
int is_all_zeros_htf(const unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}

// Generate some random seed data
void generate_random_seed_htf(unsigned char* seed, int len)
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

int main()
{
    printf("=== Hash-to-Field Test ===\n\n");

    // Test 1: Basic hash-to-field operation
    printf("1. Testing basic hash-to-field operation...\n");

    // Test data
    const unsigned char dst[] = "CVC_TEST_DST";
    const unsigned char message[] = "Hello, World!";
    FP_NIST256 field_elements[2];

    const int test1_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst,
        sizeof(dst) - 1, // -1 to exclude null terminator
        message, sizeof(message) - 1,
        2, // Generate 2 field elements
        field_elements);

    printf("   Result code: %d\n", test1_result);
    printf("   Expected: %d (CVC_HASH_TO_FIELD_SUCCESS)\n", CVC_HASH_TO_FIELD_SUCCESS);
    int test1_success = (test1_result == CVC_HASH_TO_FIELD_SUCCESS);
    printf("   Status: %s\n", test1_success ? "✅ PASSED" : "❌ FAILED");

    // Verify field elements are different (with high probability)
    if (test1_success)
    {
        // Convert field elements back to BIG for comparison
        BIG_256_56 big1, big2;
        FP_NIST256_redc(big1, &field_elements[0]);
        FP_NIST256_redc(big2, &field_elements[1]);

        const int elements_different = (BIG_256_56_comp(big1, big2) != 0);
        printf("   Field elements are different: %s\n", elements_different ? "✅ YES" : "❌ NO");
        test1_success = elements_different;

        // Check that elements are not zero
        const int elem1_nonzero = !BIG_256_56_iszilch(big1);
        const int elem2_nonzero = !BIG_256_56_iszilch(big2);
        printf("   Element 1 is non-zero: %s\n", elem1_nonzero ? "✅ YES" : "❌ NO");
        printf("   Element 2 is non-zero: %s\n", elem2_nonzero ? "✅ YES" : "❌ NO");
        test1_success = test1_success && elem1_nonzero && elem2_nonzero;
    }
    printf("\n");

    // Test 2: Invalid parameters
    printf("2. Testing invalid parameters...\n");

    FP_NIST256 dummy_elements[1];

    // Test 2a: NULL DST
    const int test2a_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, NULL, 10, message, sizeof(message) - 1, 1, dummy_elements);
    printf("   NULL DST result: %d\n", test2a_result);

    // Test 2b: NULL message
    const int test2b_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, sizeof(dst) - 1, NULL, 10, 1, dummy_elements);
    printf("   NULL message result: %d\n", test2b_result);

    // Test 2c: NULL field elements
    const int test2c_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, sizeof(dst) - 1, message, sizeof(message) - 1, 1, NULL);
    printf("   NULL field elements result: %d\n", test2c_result);

    // Test 2d: Zero count
    const int test2d_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, sizeof(dst) - 1, message, sizeof(message) - 1, 0, dummy_elements);
    printf("   Zero count result: %d\n", test2d_result);

    const int test2_success =
        (test2a_result == CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS) && (test2b_result == CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS) && (test2c_result == CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS) && (test2d_result == CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS);

    printf("   Expected: %d (CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS)\n", CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS);
    printf("   Status: %s\n\n", test2_success ? "✅ PASSED" : "❌ FAILED");

    // Test 3: Deterministic behavior
    printf("3. Testing deterministic behavior...\n");

    FP_NIST256 elements_a[1], elements_b[1];

    // Same inputs should produce same outputs
    const int test3a_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, sizeof(dst) - 1, message, sizeof(message) - 1, 1, elements_a);
    const int test3b_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, sizeof(dst) - 1, message, sizeof(message) - 1, 1, elements_b);

    printf("   First call result: %d\n", test3a_result);
    printf("   Second call result: %d\n", test3b_result);

    int test3_success = (test3a_result == CVC_HASH_TO_FIELD_SUCCESS) && (test3b_result == CVC_HASH_TO_FIELD_SUCCESS);

    if (test3_success)
    {
        BIG_256_56 big_a, big_b;
        FP_NIST256_redc(big_a, &elements_a[0]);
        FP_NIST256_redc(big_b, &elements_b[0]);

        const int results_equal = (BIG_256_56_comp(big_a, big_b) == 0);
        printf("   Results are identical: %s\n", results_equal ? "✅ YES" : "❌ NO");
        test3_success = results_equal;
    }
    printf("   Status: %s\n\n", test3_success ? "✅ PASSED" : "❌ FAILED");

    // Test 4: Basic secret key derivation
    printf("4. Testing basic secret key derivation...\n");

    unsigned char master_key[32];
    generate_random_seed_htf(master_key, 32);
    const unsigned char context[] = "test_context";
    const unsigned char derive_dst[] = "CVC_DERIVE_KEY";
    nist256_key_material_t derived_key;

    const int test4_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &derived_key);

    printf("   Result code: %d\n", test4_result);
    printf("   Expected: %d (CVC_DERIVE_KEY_SUCCESS)\n", CVC_DERIVE_KEY_SUCCESS);
    int test4_success = (test4_result == CVC_DERIVE_KEY_SUCCESS);

    if (test4_success)
    {
        // Check that derived key components are non-zero
        const int private_nonzero = !is_all_zeros_htf(derived_key.private_key_bytes, 32);
        const int public_x_nonzero = !is_all_zeros_htf(derived_key.public_key_x_bytes, 32);
        const int public_y_nonzero = !is_all_zeros_htf(derived_key.public_key_y_bytes, 32);

        printf("   Private key is non-zero: %s\n", private_nonzero ? "✅ YES" : "❌ NO");
        printf("   Public key X is non-zero: %s\n", public_x_nonzero ? "✅ YES" : "❌ NO");
        printf("   Public key Y is non-zero: %s\n", public_y_nonzero ? "✅ YES" : "❌ NO");

        test4_success = private_nonzero && public_x_nonzero && public_y_nonzero;

        // Display sample of derived key material
        print_hex_htf("Private key (first 16 bytes)", derived_key.private_key_bytes, 16);
        print_hex_htf("Public key X (first 16 bytes)", derived_key.public_key_x_bytes, 16);
    }
    printf("   Status: %s\n\n", test4_success ? "✅ PASSED" : "❌ FAILED");

    // Test 5: Secret key derivation - invalid parameters
    printf("5. Testing secret key derivation invalid parameters...\n");

    nist256_key_material_t dummy_key;

    // Test 5a: NULL master key
    const int test5a_result = cvc_derive_secret_key_nist256(NULL, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &dummy_key);

    // Test 5b: NULL context
    const int test5b_result = cvc_derive_secret_key_nist256(master_key, 32, NULL, 10, derive_dst, sizeof(derive_dst) - 1, &dummy_key);

    // Test 5c: NULL DST
    const int test5c_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, NULL, 10, &dummy_key);

    // Test 5d: NULL output
    const int test5d_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, NULL);

    printf("   NULL master key result: %d\n", test5a_result);
    printf("   NULL context result: %d\n", test5b_result);
    printf("   NULL DST result: %d\n", test5c_result);
    printf("   NULL output result: %d\n", test5d_result);

    const int test5_success =
        (test5a_result == CVC_DERIVE_KEY_ERROR_INVALID_PARAMS) && (test5b_result == CVC_DERIVE_KEY_ERROR_INVALID_PARAMS) && (test5c_result == CVC_DERIVE_KEY_ERROR_INVALID_PARAMS) && (test5d_result == CVC_DERIVE_KEY_ERROR_INVALID_PARAMS);

    printf("   Expected: %d (CVC_DERIVE_KEY_ERROR_INVALID_PARAMS)\n", CVC_DERIVE_KEY_ERROR_INVALID_PARAMS);
    printf("   Status: %s\n\n", test5_success ? "✅ PASSED" : "❌ FAILED");

    // Test 6: Secret key derivation - deterministic behavior
    printf("6. Testing secret key derivation deterministic behavior...\n");

    nist256_key_material_t key_a, key_b;

    // Same inputs should produce same outputs
    const int test6a_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &key_a);
    const int test6b_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &key_b);

    printf("   First derivation result: %d\n", test6a_result);
    printf("   Second derivation result: %d\n", test6b_result);

    int test6_success = (test6a_result == CVC_DERIVE_KEY_SUCCESS) && (test6b_result == CVC_DERIVE_KEY_SUCCESS);

    if (test6_success)
    {
        const int private_equal = bytes_equal_htf(key_a.private_key_bytes, key_b.private_key_bytes, 32);
        const int public_x_equal = bytes_equal_htf(key_a.public_key_x_bytes, key_b.public_key_x_bytes, 32);
        const int public_y_equal = bytes_equal_htf(key_a.public_key_y_bytes, key_b.public_key_y_bytes, 32);

        printf("   Private keys are identical: %s\n", private_equal ? "✅ YES" : "❌ NO");
        printf("   Public X coords are identical: %s\n", public_x_equal ? "✅ YES" : "❌ NO");
        printf("   Public Y coords are identical: %s\n", public_y_equal ? "✅ YES" : "❌ NO");

        test6_success = private_equal && public_x_equal && public_y_equal;
    }
    printf("   Status: %s\n\n", test6_success ? "✅ PASSED" : "❌ FAILED");

    // Test 7: Secret key derivation - different inputs produce different outputs
    printf("7. Testing secret key derivation with different inputs...\n");

    unsigned char different_master_key[32];
    generate_random_seed_htf(different_master_key, 32);
    // Ensure it's different
    different_master_key[0] = ~master_key[0];
    different_master_key[1] = ~master_key[1];

    nist256_key_material_t key_original, key_different;

    const int test7a_result = cvc_derive_secret_key_nist256(master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &key_original);
    const int test7b_result = cvc_derive_secret_key_nist256(different_master_key, 32, context, sizeof(context) - 1, derive_dst, sizeof(derive_dst) - 1, &key_different);

    printf("   Original derivation result: %d\n", test7a_result);
    printf("   Different input derivation result: %d\n", test7b_result);

    int test7_success = (test7a_result == CVC_DERIVE_KEY_SUCCESS) && (test7b_result == CVC_DERIVE_KEY_SUCCESS);

    if (test7_success)
    {
        const int private_different = !bytes_equal_htf(key_original.private_key_bytes, key_different.private_key_bytes, 32);
        const int public_x_different = !bytes_equal_htf(key_original.public_key_x_bytes, key_different.public_key_x_bytes, 32);
        const int public_y_different = !bytes_equal_htf(key_original.public_key_y_bytes, key_different.public_key_y_bytes, 32);

        printf("   Private keys are different: %s\n", private_different ? "✅ YES" : "❌ NO");
        printf("   Public X coords are different: %s\n", public_x_different ? "✅ YES" : "❌ NO");
        printf("   Public Y coords are different: %s\n", public_y_different ? "✅ YES" : "❌ NO");

        test7_success = private_different && public_x_different && public_y_different;
    }
    printf("   Status: %s\n\n", test7_success ? "✅ PASSED" : "❌ FAILED");

    // Summary
    printf("=== Hash-to-Field Test Summary ===\n");
    const int all_tests_passed = test1_success && test2_success && test3_success && test4_success && test5_success && test6_success && test7_success;

    if (all_tests_passed)
    {
        printf("🎉 All hash-to-field tests PASSED! The functions are working correctly.\n");
        printf("✅ Basic hash-to-field operation: PASSED\n");
        printf("✅ Invalid parameter handling: PASSED\n");
        printf("✅ Deterministic behavior: PASSED\n");
        printf("✅ Secret key derivation: PASSED\n");
        printf("✅ Key derivation parameter validation: PASSED\n");
        printf("✅ Key derivation deterministic behavior: PASSED\n");
        printf("✅ Different inputs produce different outputs: PASSED\n");
        return 0;
    }
    else
    {
        printf("💥 Some hash-to-field tests FAILED! Check the output above for details.\n");
        return 1;
    }
}
