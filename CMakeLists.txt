#MIT License
#
#Copyright (c) 2025 Peter Paravinja
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

cmake_minimum_required(VERSION 3.19)
project(cvc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(CVC_MAJOR 0)
set(CVC_MINOR 2)
set(CVC_PATCH 27)
set(CVC_VERSION_STRING "${CVC_MAJOR}.${CVC_MINOR}.${CVC_PATCH}")

# ============================================================================
# WINDOWS: Disable MSVC security features for MinGW/CGO compatibility
# ============================================================================
if(WIN32 AND CMAKE_C_COMPILER_ID MATCHES "MSVC")
    message(STATUS "Windows MSVC detected - disabling security features for MinGW/CGO compatibility")

    # Disable Buffer Security Check and SDL checks to avoid __security_cookie symbols
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS- /sdl-")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS- /sdl-")

    # Use static runtime to avoid DLL dependencies
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

    # Disable warnings for deprecated functions and add compatibility definitions
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

    # Disable additional security features that could introduce incompatible symbols
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf-")  # Disable Control Flow Guard
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /guard:cf-")

    message(STATUS "Applied MSVC compatibility flags: /GS- /sdl- /guard:cf- /MT")
endif()

# For MinGW compatibility when using GCC/Clang on Windows
if(WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang"))
    message(STATUS "Windows GCC/Clang detected - applying MinGW compatibility flags")

    # Disable stack protection for consistency with MSVC /GS-
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

    # Static linking for MinGW
    if(MINGW)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()

    message(STATUS "Applied MinGW compatibility flags: -fno-stack-protector")
endif()

# Detect iOS build and prepare appropriate compiler flags
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Configuring for iOS build")
    set(IS_IOS_BUILD TRUE)

    # Set iOS deployment target if not already set
    if (NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "18.0")
    endif ()

    # Determine iOS platform (device vs simulator) - case insensitive match
    string(TOLOWER "${CMAKE_OSX_SYSROOT}" CMAKE_OSX_SYSROOT_LOWER)
    if (CMAKE_OSX_SYSROOT_LOWER MATCHES ".*iphonesimulator.*")
        set(IOS_PLATFORM "simulator")
        message(STATUS "Building for iOS Simulator")
    else ()
        set(IOS_PLATFORM "device")
        message(STATUS "Building for iOS Device")
    endif ()

    # *** NEW: Add global iOS flags for l8w8jwt inheritance ***
    # Set target flags that will be inherited by ALL subdirectories
    if (CMAKE_OSX_SYSROOT MATCHES "iphoneos")
        set(GLOBAL_IOS_TARGET "-target arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}")
    elseif (CMAKE_OSX_SYSROOT MATCHES "iphonesimulator")
        set(GLOBAL_IOS_TARGET "-target arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}-simulator")
    endif ()

    # Force these into CMAKE_C_FLAGS and CMAKE_CXX_FLAGS so ALL subdirectories inherit them
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GLOBAL_IOS_TARGET}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GLOBAL_IOS_TARGET}")

    if (CMAKE_OSX_SYSROOT)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isysroot ${CMAKE_OSX_SYSROOT}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isysroot ${CMAKE_OSX_SYSROOT}")
    endif ()

    message(STATUS "Global iOS target flags for inheritance: ${GLOBAL_IOS_TARGET}")
    # *** END NEW SECTION ***
else ()
    set(IS_IOS_BUILD FALSE)
endif ()

# Build miracl-core library with correct cross-compilation environment
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # Build clean MIRACL-specific CFLAGS from scratch
    set(MIRACL_CFLAGS "")

    # Add architecture flag
    set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -arch ${CMAKE_OSX_ARCHITECTURES}")

    # Add sysroot
    if (CMAKE_OSX_SYSROOT)
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -isysroot ${CMAKE_OSX_SYSROOT}")
    endif ()

    # FIX: Add the proper target triple for iOS vs iOS Simulator
    if (IOS_PLATFORM STREQUAL "simulator")
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -target arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}-simulator")
    else ()
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -target arm64-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}")
    endif ()

    # Clean up any leading/trailing whitespace
    string(STRIP "${MIRACL_CFLAGS}" MIRACL_CFLAGS)

    message(STATUS "MIRACL CFLAGS: ${MIRACL_CFLAGS}")

    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a
            COMMAND ${CMAKE_COMMAND} -E env
            CC=${CMAKE_C_COMPILER}
            CFLAGS=${MIRACL_CFLAGS}
            python3 config64.py -o 3 -o 1
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
            COMMENT "Building MIRACL core library for iOS with proper cross-compilation"
    )
else ()
    # Build for non-iOS platforms - build clean CFLAGS for consistency
    set(MIRACL_CFLAGS "")

    # Add architecture flag for macOS if specified
    if (APPLE AND CMAKE_OSX_ARCHITECTURES)
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -arch ${CMAKE_OSX_ARCHITECTURES}")
    endif ()

    # ============================================================================
    # WINDOWS: Add MIRACL-specific compatibility flags
    # ============================================================================
    if(WIN32)
        # Apply same compatibility flags to MIRACL build
        if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
            # For MSVC: disable security features that cause linking issues
            set(MIRACL_CFLAGS "${MIRACL_CFLAGS} /GS- /sdl- /guard:cf- /MT")
            message(STATUS "MIRACL MSVC compatibility flags: /GS- /sdl- /guard:cf- /MT")
        elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
            # For MinGW/GCC: disable stack protection
            set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -fno-stack-protector")
            if(MINGW)
                set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -static-libgcc")
            endif()
            message(STATUS "MIRACL MinGW compatibility flags: -fno-stack-protector")
        endif()
    endif()

    # Clean up any leading/trailing whitespace
    string(STRIP "${MIRACL_CFLAGS}" MIRACL_CFLAGS)

    if (WIN32)
        # Windows: Use cmd.exe compatible path escaping
        string(REPLACE "/" "\\" CMAKE_C_COMPILER_WIN "${CMAKE_C_COMPILER}")
        add_custom_command(
                OUTPUT ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a
                COMMAND ${CMAKE_COMMAND} -E env
                "CC=${CMAKE_C_COMPILER_WIN}"
                "CFLAGS=${MIRACL_CFLAGS}"
                python3 config64.py -o 3 -o 1
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
                COMMENT "Building MIRACL core library with Windows compatibility flags"
        )
    else ()
        add_custom_command(
                OUTPUT ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a
                COMMAND ${CMAKE_COMMAND} -E env
                CC=${CMAKE_C_COMPILER}
                CFLAGS=${MIRACL_CFLAGS}
                python3 config64.py -o 3 -o 1
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
                COMMENT "Building MIRACL core library with cross-compilation toolchain"
        )
    endif ()
endif ()

add_custom_target(miracl_core DEPENDS ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a)

# ENHANCED: Force iOS configuration for ALL l8w8jwt sub-libraries (especially mbedtls)
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # Set cache variables that will be inherited by ALL subdirectories and sub-subdirectories
    set(CMAKE_SYSTEM_NAME "iOS" CACHE STRING "Target system" FORCE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "${CMAKE_OSX_DEPLOYMENT_TARGET}" CACHE STRING "iOS deployment target" FORCE)
    set(CMAKE_OSX_ARCHITECTURES "${CMAKE_OSX_ARCHITECTURES}" CACHE STRING "iOS architectures" FORCE)
    set(CMAKE_OSX_SYSROOT "${CMAKE_OSX_SYSROOT}" CACHE PATH "iOS SDK path" FORCE)

    # Force compiler and flags for all sub-projects
    set(CMAKE_C_COMPILER "${CMAKE_C_COMPILER}" CACHE FILEPATH "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER "${CMAKE_CXX_COMPILER}" CACHE FILEPATH "CXX compiler" FORCE)

    # CRITICAL: Force mbedtls to disable programs and tests (they cause platform issues)
    set(ENABLE_TESTING OFF CACHE BOOL "Build MbedTLS tests." FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Build MbedTLS example programs." FORCE)

    # Set policy to ensure subdirectories inherit these settings
    cmake_policy(SET CMP0077 NEW)

    message(STATUS "Forced iOS settings for all l8w8jwt sub-libraries including mbedtls")
endif ()

# ============================================================================
# WINDOWS: Configure l8w8jwt with compatibility flags
# ============================================================================
if(WIN32)
    message(STATUS "Configuring l8w8jwt with Windows compatibility settings")

    # Force l8w8jwt and mbedtls to use same security settings
    set(ENABLE_TESTING OFF CACHE BOOL "Build MbedTLS tests." FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Build MbedTLS example programs." FORCE)

    # Apply same policy for consistency
    cmake_policy(SET CMP0077 NEW)
endif()

# Add l8w8jwt subdirectory and build as static library
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum CMake policy version" FORCE)

# CRITICAL: Disable l8w8jwt's own tests and examples for iOS to prevent platform mixing
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(L8W8JWT_ENABLE_TESTS OFF CACHE BOOL "Build l8w8jwt tests." FORCE)
    set(L8W8JWT_ENABLE_EXAMPLES OFF CACHE BOOL "Build l8w8jwt example programs." FORCE)
    set(L8W8JWT_ENABLE_EDDSA OFF CACHE BOOL "Build the library with EdDSA support." FORCE)
endif ()

# Windows: Also disable l8w8jwt tests/examples for consistency
if(WIN32)
    set(L8W8JWT_ENABLE_TESTS OFF CACHE BOOL "Build l8w8jwt tests." FORCE)
    set(L8W8JWT_ENABLE_EXAMPLES OFF CACHE BOOL "Build l8w8jwt example programs." FORCE)
endif()

add_subdirectory(libs/l8w8jwt)

# Create our main library (just our source files)
add_library(cvc_base STATIC
        src/crypto.c
        src/nist256_key_material.c
        src/ecp_operations.c
        src/hash_to_field.c
        src/add_secret_keys.c
)

add_dependencies(cvc_base miracl_core)

# ============================================================================
# WINDOWS: Apply compatibility flags to our library
# ============================================================================
if(WIN32 AND CMAKE_C_COMPILER_ID MATCHES "MSVC")
    # Apply same security disabling flags to our library
    target_compile_options(cvc_base PRIVATE
            /GS-           # Disable security cookies
            /sdl-          # Disable SDL checks
            /guard:cf-     # Disable Control Flow Guard
            /wd4996        # Disable deprecated function warnings
    )
    message(STATUS "Applied MSVC compatibility flags to cvc_base library")
elseif(WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang"))
    # Apply MinGW compatibility flags
    target_compile_options(cvc_base PRIVATE
            -fno-stack-protector
    )
    message(STATUS "Applied MinGW compatibility flags to cvc_base library")
endif()

# Link l8w8jwt to our base library
target_link_libraries(cvc_base
        PUBLIC
        l8w8jwt
)

# Include directories for the base library
target_include_directories(cvc_base
        PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
        ${CMAKE_SOURCE_DIR}/libs/l8w8jwt/include
)

# Platform-specific library combination
set(MIRACL_LIB ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a)

if (WIN32)
    # Windows: Use lib.exe
    set(COMBINED_LIB_ROOT ${CMAKE_BINARY_DIR}/cvc.lib)
    set(COMBINED_LIB_RELEASE ${CMAKE_BINARY_DIR}/Release/cvc.lib)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/Release)

    add_custom_command(
            OUTPUT ${COMBINED_LIB_ROOT} ${COMBINED_LIB_RELEASE}
            COMMAND ${CMAKE_COMMAND} -E echo "Creating combined library for Windows..."
            COMMAND lib.exe /OUT:${COMBINED_LIB_ROOT} $<TARGET_FILE:cvc_base> $<TARGET_FILE:l8w8jwt> ${MIRACL_LIB}
            COMMAND ${CMAKE_COMMAND} -E copy ${COMBINED_LIB_ROOT} ${COMBINED_LIB_RELEASE}
            DEPENDS cvc_base l8w8jwt miracl_core
            COMMENT "Combining all static libraries into cvc.lib using lib.exe (with MSVC compatibility)"
    )
    set(COMBINED_LIB ${COMBINED_LIB_ROOT})
elseif (APPLE)
    # macOS/iOS: Use Apple's libtool
    set(COMBINED_LIB ${CMAKE_BINARY_DIR}/libcvc.a)

    add_custom_command(
            OUTPUT ${COMBINED_LIB}
            COMMAND ${CMAKE_COMMAND} -E echo "Creating combined library using libtool..."
            COMMAND libtool -static -o ${COMBINED_LIB}
            $<TARGET_FILE:cvc_base>
            $<TARGET_FILE:l8w8jwt>
            ${MIRACL_LIB}
            DEPENDS cvc_base l8w8jwt miracl_core
            COMMENT "Combining all static libraries into libcvc.a using libtool"
    )
else ()
    # Linux: Use ar with MRI script (GNU ar feature)
    set(COMBINED_LIB ${CMAKE_BINARY_DIR}/libcvc.a)

    add_custom_command(
            OUTPUT ${COMBINED_LIB}
            COMMAND ${CMAKE_COMMAND} -E echo "Creating combined library using ar..."
            COMMAND ${CMAKE_COMMAND} -E echo "CREATE ${COMBINED_LIB}" > ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB $<TARGET_FILE:cvc_base>" >> ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB $<TARGET_FILE:l8w8jwt>" >> ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB ${MIRACL_LIB}" >> ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_COMMAND} -E echo "SAVE" >> ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_COMMAND} -E echo "END" >> ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_AR} -M < ${CMAKE_BINARY_DIR}/ar_script.mri
            COMMAND ${CMAKE_RANLIB} ${COMBINED_LIB}
            COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/ar_script.mri
            DEPENDS cvc_base l8w8jwt miracl_core
            COMMENT "Combining all static libraries into libcvc.a using ar"
    )
endif ()
# Create the temp directory for extraction
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/temp_extract)

# Create a custom target that depends on the combined library
if (WIN32)
    add_custom_target(cvc ALL DEPENDS ${COMBINED_LIB_ROOT} ${COMBINED_LIB_RELEASE})
else ()
    add_custom_target(cvc ALL DEPENDS ${COMBINED_LIB})
endif ()