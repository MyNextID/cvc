//
// Created by Peter Paravinja on 17. 7. 25.
//
#include "nist256_key_material.h"
#include <string.h>

// External ROM constants from rom_curve_NIST256.c
extern const BIG_256_56 CURVE_Order_NIST256;

int nist256_generate_secret_key(BIG_256_56 secret_key, unsigned char* random_seed, int seed_len)
{
    if (!random_seed || seed_len < 16)
    {
        return -1; // Invalid parameters - need at least 16 bytes of seed
    }

    // Initialize and seed the cryptographically secure random number generator
    csprng rng;
    RAND_clean(&rng);
    RAND_seed(&rng, seed_len, (char*)random_seed);

    // Get the NIST P-256 curve order from ROM constants
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_NIST256);

    // Generate a random number in the range [1, curve_order-1]
    // This ensures we have a valid private key (not 0 or >= curve_order)
    BIG_256_56_randomnum(secret_key, curve_order, &rng);

    // Ensure the key is not zero (extremely unlikely but theoretically possible)
    if (BIG_256_56_iszilch(secret_key))
    {
        // If we got zero, generate another random number
        BIG_256_56_randomnum(secret_key, curve_order, &rng);

        // If still zero (virtually impossible), return error
        if (BIG_256_56_iszilch(secret_key))
        {
            RAND_clean(&rng);
            return -2; // Failed to generate non-zero key
        }
    }

    // Clean up the RNG
    RAND_clean(&rng);

    return 0; // Success
}

int nist256_big_to_key_material(BIG_256_56 d, nist256_key_material_t* key_material)
{
    if (!key_material)
    {
        return -1; // Invalid parameter
    }

    // Clear the output structure
    memset(key_material, 0, sizeof(nist256_key_material_t));

    // Get the generator point G for NIST P-256
    ECP_NIST256 G;
    if (!ECP_NIST256_generator(&G))
    {
        return -3; // Failed to get generator point
    }

    // Calculate public key point: pub = d * G
    ECP_NIST256 pub;
    ECP_NIST256_copy(&pub, &G);
    ECP_NIST256_mul(&pub, d);

    // Check if the result is the point at infinity (invalid)
    if (ECP_NIST256_isinf(&pub))
    {
        return -2; // Invalid private key (resulted in point at infinity)
    }

    // Convert to affine coordinates for coordinate extraction
    ECP_NIST256_affine(&pub);

    // Extract the x and y coordinates from the public key point
    BIG_256_56 x_coord, y_coord;

    // CORRECTED: Get both coordinates in one call
    // The ECP_NIST256_get function expects BIG_256_56 parameters, not FP_NIST256
    int result = ECP_NIST256_get(x_coord, y_coord, &pub);
    if (result < 0)
    {
        return -4; // Failed to extract coordinates
    }

    // Convert BIG numbers to byte arrays
    BIG_256_56_toBytes((char*)key_material->private_key_bytes, d);
    BIG_256_56_toBytes((char*)key_material->public_key_x_bytes, x_coord);
    BIG_256_56_toBytes((char*)key_material->public_key_y_bytes, y_coord);

    return 0; // Success
}