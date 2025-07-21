#!/bin/bash
# test.sh - Build and test CVC library
# Usage: ./test.sh

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "CMakeLists.txt" ]]; then
    print_error "CMakeLists.txt not found. Run this script from the project root directory."
    exit 1
fi

print_info "Building CVC library..."

# Clean any existing build artifacts that might conflict
print_info "Cleaning any existing build artifacts..."
rm -rf CMakeCache.txt CMakeFiles/ cmake_install.cmake Makefile

# Create build directory
BUILD_DIR="build_test"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure and build
print_info "Configuring CMake..."
cmake .. || {
    print_error "CMake configuration failed"
    print_info "CMake output above should show the specific error"
    exit 1
}

print_info "Building library..."
print_info "Running: cmake --build . --verbose"
cmake --build . --verbose || {
    print_error "Build failed"
    print_info "Detailed build output above should show the specific error"
    # Show additional debugging info
    echo
    print_info "Debugging information:"
    echo "Current directory: $(pwd)"
    echo "CMake cache file exists: $(test -f CMakeCache.txt && echo 'YES' || echo 'NO')"
    echo "Makefile exists: $(test -f Makefile && echo 'YES' || echo 'NO')"
    echo "Contents of build directory:"
    ls -la
    exit 1
}

# Go back to project root
cd ..

# Check if library was created
if [[ -f "$BUILD_DIR/libcvc.a" ]]; then
    print_success "Library built successfully: $BUILD_DIR/libcvc.a"
else
    print_error "Library not found at $BUILD_DIR/libcvc.a"
    exit 1
fi

# Compile main test program
print_info "Compiling main test program..."
clang -o test_cvc tests/test_cvc.c \
    -I. \
    -I./libs/miracl-core/c \
    -I./libs/l8w8jwt/include \
    -L./$BUILD_DIR \
    -lcvc || {
    print_error "Main test compilation failed"
    exit 1
}

print_success "Main test program compiled successfully"

# Compile ECP operations test program
print_info "Compiling ECP operations test program..."
clang -o test_ecp_operations tests/test_ecp_operations.c \
    -I. \
    -I./libs/miracl-core/c \
    -I./libs/l8w8jwt/include \
    -L./$BUILD_DIR \
    -lcvc || {
    print_error "ECP operations test compilation failed"
    exit 1
}

print_success "ECP operations test program compiled successfully"

# Compile hash-to-field test program
print_info "Compiling hash-to-field test program..."
clang -o test_hash_to_field tests/test_hash_to_field.c \
    -I. \
    -I./libs/miracl-core/c \
    -I./libs/l8w8jwt/include \
    -L./$BUILD_DIR \
    -lcvc || {
    print_error "Hash-to-field test compilation failed"
    exit 1
}

print_success "Hash-to-field test program compiled successfully"

# Run main tests
print_info "Running main tests..."
echo
./test_cvc
MAIN_TEST_RESULT=$?

echo
print_info "Running ECP operations tests..."
echo
./test_ecp_operations
ECP_TEST_RESULT=$?

echo
print_info "Running hash-to-field tests..."
echo
./test_hash_to_field
HTF_TEST_RESULT=$?

# Cleanup
rm -f test_cvc test_ecp_operations test_hash_to_field

# Evaluate results
if [[ $MAIN_TEST_RESULT -eq 0 && $ECP_TEST_RESULT -eq 0 && $HTF_TEST_RESULT -eq 0 ]]; then
    print_success "All tests passed! 🎉"
    print_info "Your library is ready for Go integration"
    print_info "✅ Main CVC library functions: PASSED"
    print_info "✅ ECP operations (public key addition): PASSED"
    print_info "✅ Hash-to-field operations: PASSED"
else
    print_error "Some tests failed!"
    if [[ $MAIN_TEST_RESULT -ne 0 ]]; then
        print_error "❌ Main CVC library tests: FAILED"
    else
        print_success "✅ Main CVC library tests: PASSED"
    fi

    if [[ $ECP_TEST_RESULT -ne 0 ]]; then
        print_error "❌ ECP operations tests: FAILED"
    else
        print_success "✅ ECP operations tests: PASSED"
    fi

    if [[ $HTF_TEST_RESULT -ne 0 ]]; then
        print_error "❌ Hash-to-field tests: FAILED"
    else
        print_success "✅ Hash-to-field tests: PASSED"
    fi
    
    print_info "Check the output above for details"
    exit 1
fi