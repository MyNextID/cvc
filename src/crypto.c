//
// Created by Peter Paravinja on 10. 7. 25.
//

#include "crypto.h"
#include "ecp_Ed25519.h"

const char* cvc_hello_world(void) {
    return "Hello World from CVC Library";
}

// Simple test function that uses MIRACL Ed25519 operations
int cvc_test_miracl_big_add(void) {
    ECP_Ed25519 G;

    // Try to get the generator point for Ed25519
    int result = ECP_Ed25519_generator(&G);

    // Return 1 if successful (generator point created), 0 if failed
    return result;
}