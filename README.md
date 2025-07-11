# CVC - Cryptographic Library

A C library for cryptographic operations designed for iOS, Android, and Golang SDK integration.

## Build System

This project uses **CMake** for building and managing dependencies.

## Dependencies

We use **Git Submodules** to manage two external cryptographic libraries:

### 1. miracl-core
- **Purpose**: Elliptic curve cryptography
- **Build Method**: Python script (`python3 config64.py -o 3 -o 1`)
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


## Release Process

We use an automated release workflow to build cross-platform binaries and create GitHub releases.

### Creating a Release

1. **Update version**: Modify the version numbers in `CMakeLists.txt`:
   ```cmake
   set(CVC_MAJOR 1)
   set(CVC_MINOR 1)
   set(CVC_PATCH 1)
   ```

2. **Create release tag**: Run the release script:
   ```bash
   ./release.sh
   ```
   This automatically creates a git tag from the CMakeLists.txt version and pushes it to GitHub.

3. **Automated build**: The tag triggers a GitHub Actions workflow that builds static libraries for:
    - **macOS**: arm64, x86_64
    - **Linux**: x86_64, aarch64
    - **Windows**: x86_64

4. **GitHub Release**: Once builds complete, a new release is automatically created with downloadable archives containing the static libraries and headers for each platform.

The release artifacts include the compiled static library (`.a`/`.lib`) and all necessary headers for integration into iOS, Android, and Golang projects.
