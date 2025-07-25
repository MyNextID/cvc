//
// Created by Peter Paravinja on 25. 7. 25.
//
#include "add_secret_keys.h"
#include "big_256_56.h"
#include "core.h"
#include <string.h>

// External ROM constants
extern const BIG_256_56 CURVE_Order_NIST256;

int cvc_add_nist256_secret_keys(const unsigned char* key1_bytes, int key1_len, const unsigned char* key2_bytes, int key2_len, nist256_key_material_t* result_key_material)
{
    // Basic parameter validation
    if (!key1_bytes || key1_len != MODBYTES_256_56 || !key2_bytes || key2_len != MODBYTES_256_56 || !result_key_material)
    {
        return CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS;
    }

    // Clear the output structure
    memset(result_key_material, 0, sizeof(nist256_key_material_t));

    // Get curve order from ROM
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_NIST256);

    // Convert input key bytes to BIG numbers
    BIG_256_56 d1, d2;
    BIG_256_56_fromBytes(d1, (char*)key1_bytes);
    BIG_256_56_fromBytes(d2, (char*)key2_bytes);

    // Validate that both keys are in valid range [1, curve_order-1]
    // Check key1 is not zero and not >= curve_order
    if (BIG_256_56_iszilch(d1) || BIG_256_56_comp(d1, curve_order) >= 0)
    {
        return CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1;
    }

    // Check key2 is not zero and not >= curve_order
    if (BIG_256_56_iszilch(d2) || BIG_256_56_comp(d2, curve_order) >= 0)
    {
        return CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY2;
    }

    // Perform scalar addition: sum = (d1 + d2) mod curve_order
    BIG_256_56 sum;
    BIG_256_56_copy(sum, d1);         // sum = d1
    BIG_256_56_add(sum, sum, d2);     // sum = d1 + d2
    BIG_256_56_mod(sum, curve_order); // sum = (d1 + d2) mod curve_order

    // Ensure result is not zero (extremely unlikely but theoretically possible)
    if (BIG_256_56_iszilch(sum))
    {
        return CVC_ADD_SECRET_KEYS_ERROR_RESULT_ZERO;
    }

    // Extract complete key material using existing function
    int extract_result = nist256_big_to_key_material(sum, result_key_material);
    if (extract_result != 0)
    {
        return CVC_ADD_SECRET_KEYS_ERROR_KEY_EXTRACTION_FAILED;
    }

    return CVC_ADD_SECRET_KEYS_SUCCESS;
}