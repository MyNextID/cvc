//
// Created by Peter Paravinja on 21. 7. 25.
//
#include "ecp_operations.h"
#include "ecp_NIST256.h"
#include "ecdh_NIST256.h"
#include "core.h"
#include <string.h>

// Expected length for uncompressed NIST P-256 public key (0x04 + 32 bytes X + 32 bytes Y)
#define NIST256_UNCOMPRESSED_KEY_LENGTH (2 * EFS_NIST256 + 1) // 65 bytes

int cvc_add_nist256_public_keys(const unsigned char* key1_bytes, int key1_len, const unsigned char* key2_bytes, int key2_len, unsigned char* result_bytes, int result_buffer_size, int* actual_result_len)
{
    // Validate input key lengths
    if (key1_len != NIST256_UNCOMPRESSED_KEY_LENGTH)
    {
        return CVC_ECP_ERROR_INVALID_KEY1_LENGTH;
    }

    if (key2_len != NIST256_UNCOMPRESSED_KEY_LENGTH)
    {
        return CVC_ECP_ERROR_INVALID_KEY2_LENGTH;
    }

    // Check if result buffer is large enough
    if (result_buffer_size < NIST256_UNCOMPRESSED_KEY_LENGTH)
    {
        return CVC_ECP_ERROR_INSUFFICIENT_BUFFER;
    }

    // Create octet structures for MIRACL
    octet key1_octet = { key1_len, key1_len, (char*)key1_bytes };
    octet key2_octet = { key2_len, key2_len, (char*)key2_bytes };

    // Parse first public key from bytes to ECP point
    ECP_NIST256 point1;
    if (!ECP_NIST256_fromOctet(&point1, &key1_octet))
    {
        return CVC_ECP_ERROR_INVALID_POINT_1;
    }

    // Check if first point is at infinity (invalid)
    if (ECP_NIST256_isinf(&point1))
    {
        return CVC_ECP_ERROR_POINT_1_AT_INFINITY;
    }

    // Parse second public key from bytes to ECP point
    ECP_NIST256 point2;
    if (!ECP_NIST256_fromOctet(&point2, &key2_octet))
    {
        return CVC_ECP_ERROR_INVALID_POINT_2;
    }

    // Check if second point is at infinity (invalid)
    if (ECP_NIST256_isinf(&point2))
    {
        return CVC_ECP_ERROR_POINT_2_AT_INFINITY;
    }

    // Create result point and copy first point to it
    ECP_NIST256 result_point;
    ECP_NIST256_copy(&result_point, &point1);

    // Add the second point to the result
    ECP_NIST256_add(&result_point, &point2);

    // Check if result is at infinity (which would be invalid)
    if (ECP_NIST256_isinf(&result_point))
    {
        return CVC_ECP_ERROR_RESULT_AT_INFINITY;
    }

    // Convert result back to bytes (uncompressed format)
    octet result_octet = { 0, result_buffer_size, (char*)result_bytes };
    ECP_NIST256_toOctet(&result_octet, &result_point, false); // false = uncompressed

    // Verify the conversion was successful and the result has expected length
    if (result_octet.len != NIST256_UNCOMPRESSED_KEY_LENGTH)
    {
        return CVC_ECP_ERROR_RESULT_CONVERSION_FAILED;
    }

    // Set the actual result length
    *actual_result_len = result_octet.len;

    return CVC_ECP_SUCCESS;
}