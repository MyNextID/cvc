//
// Created by Peter Paravinja on 14. 7. 25.
//

#include <stdio.h>
#include <stdlib.h>
#include "src/crypto.h"

int main() {
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

    // Summary
    printf("=== Test Summary ===\n");
    if (hello_result != NULL && miracl_result == 1) {
        printf("🎉 All tests PASSED! CVC library is working correctly.\n");
        return 0;
    } else {
        printf("💥 Some tests FAILED! Check the library integration.\n");
        return 1;
    }
}