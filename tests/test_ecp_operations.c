//
// Created by Peter Paravinja on 21. 7. 25.
//
#include <stdio.h>
#include <string.h>
#include "src/ecp_operations.h"
#include "src/crypto.h"
#include "src/nist256_key_material.h"

// Helper function to print hex bytes
void print_hex_ecp(const char *label, const unsigned char *data, int len) {
    printf("   %s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1 && (i + 1) % 16 == 0)
            printf("\n        ");
        else if (i < len - 1 && (i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n");
}

// Helper function to compare two byte arrays
int bytes_equal_ecp(const unsigned char *a, const unsigned char *b, int len) {
    return memcmp(a, b, len) == 0;
}

// Helper function to generate a valid NIST P-256 public key from seed
int generate_valid_nist256_key(unsigned char *key_bytes, unsigned char *seed, int seed_len) {
    // Generate private key from seed
    BIG_256_56 private_key;
    if (nist256_generate_secret_key(private_key, seed, seed_len) != 0) {
        return -1;
    }

    // Extract key material including public key coordinates
    nist256_key_material_t key_material;
    if (nist256_big_to_key_material(private_key, &key_material) != 0) {
        return -2;
    }

    // Format as uncompressed public key: 0x04 || X || Y
    key_bytes[0] = 0x04; // Uncompressed point indicator
    memcpy(&key_bytes[1], key_material.public_key_x_bytes, 32);
    memcpy(&key_bytes[33], key_material.public_key_y_bytes, 32);

    return 0;
}

// Generate some random seed data
void generate_random_seed(unsigned char *seed, int len) {
    // Simple pseudo-random for testing (not cryptographically secure for production)
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int) time(NULL));
        seeded = 1;
    }
    for (int i = 0; i < len; i++) {
        seed[i] = (unsigned char) (rand() & 0xFF);
    }
}

// Invalid key - wrong length (64 bytes instead of 65)
static const unsigned char invalid_key_wrong_length[64] = {
    // Missing the 0x04 prefix, making it 64 bytes instead of 65
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
    0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A,
    0x7F, 0x9B, 0x8E, 0xE7,
    0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37,
    0xBF, 0x51, 0xF5
};

// Invalid key - correct length but invalid point data
static const unsigned char invalid_key_bad_point[65] = {
    0x04, // Uncompressed point indicator
    // Invalid X coordinate (all zeros - not a valid point)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Invalid Y coordinate (all zeros)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main() {
    printf("=== ECP Operations Test ===\n\n");

    // Generate valid test keys dynamically
    unsigned char test_key1[65], test_key2[65];
    unsigned char seed1[32], seed2[32];

    printf("0. Generating valid test keys...\n");
    generate_random_seed(seed1, 32);
    generate_random_seed(seed2, 32);
    // Make sure seeds are different
    seed2[0] = ~seed1[0];
    seed2[1] = ~seed1[1];

    if (generate_valid_nist256_key(test_key1, seed1, 32) != 0) {
        printf("   ❌ FAILED to generate test key 1\n");
        return 1;
    }

    if (generate_valid_nist256_key(test_key2, seed2, 32) != 0) {
        printf("   ❌ FAILED to generate test key 2\n");
        return 1;
    }

    printf("   ✅ Generated valid test keys\n");
    print_hex_ecp("Test Key 1 (first 16 bytes)", test_key1, 16);
    print_hex_ecp("Test Key 2 (first 16 bytes)", test_key2, 16);
    printf("\n");

    // Test 1: Valid public key addition
    printf("1. Testing valid public key addition...\n");
    unsigned char result1[65];
    int result_len1;

    int test1_result = cvc_add_nist256_public_keys(test_key1, sizeof(test_key1), test_key2, sizeof(test_key2), result1,
                                                   sizeof(result1), &result_len1);
    printf("   Result code: %d\n", test1_result);
    printf("   Result length: %d\n", result_len1);
    printf("   Expected length: 65\n");
    int test1_success = (test1_result == CVC_ECP_SUCCESS) && (result_len1 == 65);
    printf("   Status: %s\n", test1_success ? "✅ PASSED" : "❌ FAILED");
    if (test1_success) {
        print_hex_ecp("Result key (first 32 bytes)", result1, 32);
        // Verify result is not all zeros (which would indicate failure)
        int all_zeros = 1;
        for (int i = 1; i < 65; i++) {
            // Skip first byte (0x04)
            if (result1[i] != 0) {
                all_zeros = 0;
                break;
            }
        }
        printf("   Result is non-zero: %s\n", all_zeros ? "❌ NO" : "✅ YES");
        test1_success = test1_success && !all_zeros;
    }
    printf("\n");

    // Test 2: Invalid key length (first key)
    printf("2. Testing invalid first key length...\n");
    unsigned char result2[65];
    int result_len2;
    int test2_result = cvc_add_nist256_public_keys(invalid_key_wrong_length, sizeof(invalid_key_wrong_length),
                                                   // 64 bytes instead of 65
                                                   test_key2, sizeof(test_key2), result2, sizeof(result2),
                                                   &result_len2);
    printf("   Result code: %d\n", test2_result);
    printf("   Expected: %d (CVC_ECP_ERROR_INVALID_KEY1_LENGTH)\n", CVC_ECP_ERROR_INVALID_KEY1_LENGTH);
    int test2_success = (test2_result == CVC_ECP_ERROR_INVALID_KEY1_LENGTH);
    printf("   Status: %s\n\n", test2_success ? "✅ PASSED" : "❌ FAILED");

    // Test 3: Invalid key length (second key)
    printf("3. Testing invalid second key length...\n");
    unsigned char result3[65];
    int result_len3;
    int test3_result = cvc_add_nist256_public_keys(test_key1, sizeof(test_key1), invalid_key_wrong_length,
                                                   sizeof(invalid_key_wrong_length), // 64 bytes instead of 65
                                                   result3, sizeof(result3), &result_len3);
    printf("   Result code: %d\n", test3_result);
    printf("   Expected: %d (CVC_ECP_ERROR_INVALID_KEY2_LENGTH)\n", CVC_ECP_ERROR_INVALID_KEY2_LENGTH);
    int test3_success = (test3_result == CVC_ECP_ERROR_INVALID_KEY2_LENGTH);
    printf("   Status: %s\n\n", test3_success ? "✅ PASSED" : "❌ FAILED");

    // Test 4: Insufficient buffer size
    printf("4. Testing insufficient buffer size...\n");
    unsigned char small_result[32]; // Too small - only 32 bytes instead of 65
    int result_len4;
    int test4_result = cvc_add_nist256_public_keys(test_key1, sizeof(test_key1), test_key2, sizeof(test_key2),
                                                   small_result, sizeof(small_result), &result_len4);
    printf("   Result code: %d\n", test4_result);
    printf("   Expected: %d (CVC_ECP_ERROR_INSUFFICIENT_BUFFER)\n", CVC_ECP_ERROR_INSUFFICIENT_BUFFER);
    int test4_success = (test4_result == CVC_ECP_ERROR_INSUFFICIENT_BUFFER);
    printf("   Status: %s\n\n", test4_success ? "✅ PASSED" : "❌ FAILED");

    // Test 5: Invalid point data (first key)
    printf("5. Testing invalid first point data...\n");
    unsigned char result5[65];
    int result_len5;
    int test5_result = cvc_add_nist256_public_keys(invalid_key_bad_point, sizeof(invalid_key_bad_point), test_key2,
                                                   sizeof(test_key2), result5, sizeof(result5), &result_len5);
    printf("   Result code: %d\n", test5_result);
    printf("   Expected: %d (CVC_ECP_ERROR_INVALID_POINT_1) or similar\n", CVC_ECP_ERROR_INVALID_POINT_1);
    int test5_success = (test5_result < 0); // Any error is acceptable for invalid point
    printf("   Status: %s\n\n", test5_success ? "✅ PASSED" : "❌ FAILED");

    // Test 6: Same key addition (edge case)
    printf("6. Testing same key addition (A + A)...\n");
    unsigned char result6[65];
    int result_len6;
    int test6_result = cvc_add_nist256_public_keys(test_key1, sizeof(test_key1), test_key1, sizeof(test_key1),
                                                   // Same key
                                                   result6, sizeof(result6), &result_len6);
    printf("   Result code: %d\n", test6_result);
    printf("   Result length: %d\n", result_len6);
    // This should work (doubling a point is valid in ECC)
    int test6_success = (test6_result == CVC_ECP_SUCCESS) && (result_len6 == 65);
    printf("   Status: %s\n", test6_success ? "✅ PASSED" : "❌ FAILED");
    if (test6_success) {
        // Verify the result is different from the original key
        int same_as_original = bytes_equal_ecp(result6, test_key1, 65);
        printf("   Result different from original: %s\n", same_as_original ? "❌ NO" : "✅ YES");
        test6_success = test6_success && !same_as_original;
    }
    printf("\n");

    // Summary
    printf("=== ECP Operations Test Summary ===\n");
    int all_tests_passed = test1_success && test2_success && test3_success && test4_success && test5_success &&
                           test6_success;
    if (all_tests_passed) {
        printf("🎉 All ECP operations tests PASSED! The function is working correctly.\n");
        return 0;
    } else {
        printf("💥 Some ECP operations tests FAILED! Check the output above for details.\n");
        return 1;
    }
}
