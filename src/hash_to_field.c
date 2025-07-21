//
// Created by Peter Paravinja on 21. 7. 25.
//
#include "hash_to_field.h"
#include "fp_NIST256.h"
#include "big_256_56.h"
#include "core.h"
#include <string.h>

#include "nist256_key_material.h"

// External ROM constants
extern const BIG_256_56 CURVE_Order_NIST256;
extern const BIG_256_56 Modulus_NIST256;

// Helper function to calculate ceiling division
static int ceil_divide(const int a, const int b)
{
    return (a + b - 1) / b;
}

int cvc_hash_to_field_nist256(const int hash, const int hash_len, const unsigned char* dst, const int dst_len, const unsigned char* message, const int message_len, const int count, FP_NIST256* field_elements)
{
    // Basic parameter validationw
    if (!dst || dst_len <= 0 || !message || message_len <= 0 || count <= 0 || !field_elements)
    {
        return CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS;
    }

    // Get field modulus from ROM
    BIG_256_56 field_modulus;
    BIG_256_56_rcopy(field_modulus, Modulus_NIST256);

    // Get curve order for bit length calculation
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_NIST256);

    // Calculate parameters following RFC 9380
    int k = BIG_256_56_nbits(field_modulus);       // Field modulus bit length
    int m = BIG_256_56_nbits(curve_order);         // Curve order bit length
    int L = ceil_divide(k + ceil_divide(m, 2), 8); // Expansion length per element

    // Allocate buffer for XMD expansion
    int total_expansion_len = L * count;
    if (total_expansion_len > 2048) // Reasonable safety limit
    {
        return CVC_HASH_TO_FIELD_ERROR_EXPANSION_TOO_LARGE;
    }

    char okm_buffer[2048];
    octet OKM = { 0, sizeof(okm_buffer), okm_buffer };

    // Create octets for DST and message
    octet DST = { dst_len, dst_len, (char*)dst };
    octet MESSAGE = { message_len, message_len, (char*)message };

    // Perform XMD expansion
    XMD_Expand(hash, hash_len, &OKM, total_expansion_len, &DST, &MESSAGE);

    // Check if expansion succeeded (basic validation)
    if (OKM.len != total_expansion_len)
    {
        return CVC_HASH_TO_FIELD_ERROR_EXPAND_FAILED;
    }

    // Process each field element
    for (int i = 0; i < count; i++)
    {
        // Extract L bytes for this field element
        char fd[256]; // Should be sufficient for any reasonable L
        if (L > sizeof(fd))
        {
            return CVC_HASH_TO_FIELD_ERROR_EXPANSION_TOO_LARGE;
        }

        for (int j = 0; j < L; j++)
        {
            fd[j] = OKM.val[i * L + j];
        }

        // Convert bytes to DBIG
        DBIG_256_56 dx;
        BIG_256_56_dfromBytesLen(dx, fd, L);

        // Reduce modulo field modulus
        BIG_256_56 w;
        BIG_256_56_dmod(w, dx, field_modulus);

        // Convert to field element (Montgomery form)
        FP_NIST256_nres(&field_elements[i], w);
    }

    return CVC_HASH_TO_FIELD_SUCCESS;
}

int cvc_derive_secret_key_nist256(const unsigned char* master_key_bytes, int master_key_len, const unsigned char* context, int context_len, const unsigned char* dst, int dst_len, nist256_key_material_t* derived_key_material)
{
    // Basic parameter validation
    if (!master_key_bytes || master_key_len <= 0 || !context || context_len <= 0 || !dst || dst_len <= 0 || !derived_key_material)
    {
        return CVC_DERIVE_KEY_ERROR_INVALID_PARAMS;
    }

    // Combine master key and context
    int input_len = master_key_len + context_len;
    if (input_len > 4096) // Reasonable safety limit
    {
        return CVC_DERIVE_KEY_ERROR_INPUT_TOO_LARGE;
    }

    unsigned char input[4096];
    memcpy(input, master_key_bytes, master_key_len);
    memcpy(input + master_key_len, context, context_len);

    // Hash to field to get field element
    FP_NIST256 field_element;
    int hash_result = cvc_hash_to_field_nist256(MC_SHA2, HASH_TYPE_NIST256, dst, dst_len, input, input_len, 1, &field_element);

    if (hash_result != CVC_HASH_TO_FIELD_SUCCESS)
    {
        return CVC_DERIVE_KEY_ERROR_HASH_TO_FIELD_FAILED;
    }

    // Extract the underlying BIG from the field element
    BIG_256_56 x;
    FP_NIST256_redc(x, &field_element);

    // Reduce modulo curve order to ensure valid scalar
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_NIST256);
    BIG_256_56_mod(x, curve_order);

    // Check that we didn't get zero (extremely unlikely)
    if (BIG_256_56_iszilch(x))
    {
        return CVC_DERIVE_KEY_ERROR_ZERO_SCALAR;
    }

    // Extract key material using existing function
    int extract_result = nist256_big_to_key_material(x, derived_key_material);
    if (extract_result != 0)
    {
        return CVC_DERIVE_KEY_ERROR_KEY_EXTRACTION_FAILED;
    }

    return CVC_DERIVE_KEY_SUCCESS;
}
