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

# Compile test program
print_info "Compiling test program..."
clang -o test_cvc tests/test_cvc.c \
    -I. \
    -I./libs/miracl-core/c \
    -I./libs/l8w8jwt/include \
    -L./$BUILD_DIR \
    -lcvc || {
    print_error "Test compilation failed"
    exit 1
}

print_success "Test program compiled successfully"

# Run tests
print_info "Running tests..."
echo
./test_cvc
TEST_RESULT=$?

# Cleanup
rm -f test_cvc

if [[ $TEST_RESULT -eq 0 ]]; then
    print_success "All tests passed! 🎉"
    print_info "Your library is ready for Go integration"
else
    print_error "Tests failed! Check the output above for details"
    exit 1
fi