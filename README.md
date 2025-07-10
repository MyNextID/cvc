# CVC - Cryptographic Library

A C library for cryptographic operations designed for iOS, Android, and Golang SDK integration.

## Build System

This project uses **CMake** for building and managing dependencies.

## Dependencies

We use **Git Submodules** to manage two external cryptographic libraries:

### 1. miracl-core
- **Purpose**: Elliptic curve cryptography
- **Build Method**: Python script (`python3 config64.py -o 3`)
- **Location**: `libs/miracl-core/c`

### 2. l8w8jwt
- **Purpose**: JWT (JSON Web Token) handling
- **Build Method**: CMake integration
- **Location**: `libs/l8w8jwt`
- **Contains**: 6 additional sub-libraries in `libs/l8w8jwt/lib`

## Project Structure

```
src/           # Our library code (public API)
libs/          # External dependencies via git submodules
├── miracl-core/
└── l8w8jwt/
```

## Building

```bash
# Initialize submodules
git submodule update --init --recursive

# Configure and build
cmake .
cmake --build .
```

The output will be a static library (`.a`) suitable for iOS XCFramework packaging and cross-platform integration.