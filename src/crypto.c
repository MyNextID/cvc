//
// Created by Peter Paravinja on 10. 7. 25.
//

#include "crypto.h"
#include "big_256_56.h"

const char* cvc_hello_world(void) {
    return "Hello World from CVC Library";
}

// Simple test function that uses MIRACL BIG_256_56 operations
int cvc_test_miracl_big_add(void) {
    BIG_256_56 a, b, c;

    // Initialize big numbers
    BIG_256_56_zero(a);
    BIG_256_56_zero(b);
    BIG_256_56_zero(c);

    // Set a = 123
    BIG_256_56_inc(a, 123);

    // Set b = 456
    BIG_256_56_inc(b, 456);

    // c = a + b (should be 579)
    BIG_256_56_add(c, a, b);

    // Extract the result as an integer for verification
    // For this simple test, we know the result fits in an int
    int result = (int)c[0];  // Get the least significant chunk

    // Return 1 if correct (579), 0 if incorrect
    return (result == 579) ? 1 : 0;
}