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
set(CVC_PATCH 7)
set(CVC_VERSION_STRING "${CVC_MAJOR}.${CVC_MINOR}.${CVC_PATCH}")

# Detect iOS build and prepare appropriate compiler flags
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Configuring for iOS build")
    set(IS_IOS_BUILD TRUE)

    # Set iOS deployment target if not already set
    if (NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "18.0")
    endif ()

    # Determine iOS platform (device vs simulator)
    if (CMAKE_OSX_SYSROOT MATCHES ".*iphonesimulator.*")
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

# Build miracl-core library with correct iOS cross-compilation environment
if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # Build clean MIRACL-specific CFLAGS from scratch
    set(MIRACL_CFLAGS "")

    # Add architecture flag
    set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -arch ${CMAKE_OSX_ARCHITECTURES}")

    # Add sysroot
    if (CMAKE_OSX_SYSROOT)
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -isysroot ${CMAKE_OSX_SYSROOT}")
    endif ()

    # Add deployment target
    if (CMAKE_OSX_DEPLOYMENT_TARGET)
        if (IOS_PLATFORM STREQUAL "simulator")
            set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -mios-simulator-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
        else ()
            set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -miphoneos-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
        endif ()
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
    # Original build for non-iOS platforms - build clean CFLAGS for consistency
    set(MIRACL_CFLAGS "")

    # Add architecture flag for macOS if specified
    if (APPLE AND CMAKE_OSX_ARCHITECTURES)
        set(MIRACL_CFLAGS "${MIRACL_CFLAGS} -arch ${CMAKE_OSX_ARCHITECTURES}")
    endif ()

    # Clean up any leading/trailing whitespace
    string(STRIP "${MIRACL_CFLAGS}" MIRACL_CFLAGS)

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

add_custom_target(miracl_core DEPENDS ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a)

# Add l8w8jwt subdirectory and build as static library
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum CMake policy version" FORCE)
add_subdirectory(libs/l8w8jwt)

# Create our main library (just our source files)
add_library(cvc_base STATIC
        src/crypto.c
)

add_dependencies(cvc_base miracl_core)

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
    # Windows: Create combined library in both root and Release directory for Visual Studio compatibility
    set(COMBINED_LIB_ROOT ${CMAKE_BINARY_DIR}/cvc.lib)
    set(COMBINED_LIB_RELEASE ${CMAKE_BINARY_DIR}/Release/cvc.lib)

    # Ensure Release directory exists
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/Release)

    add_custom_command(
            OUTPUT ${COMBINED_LIB_ROOT} ${COMBINED_LIB_RELEASE}
            COMMAND ${CMAKE_COMMAND} -E echo "Creating combined library for Windows..."
            COMMAND lib.exe /OUT:${COMBINED_LIB_ROOT} $<TARGET_FILE:cvc_base> $<TARGET_FILE:l8w8jwt> ${MIRACL_LIB}
            COMMAND ${CMAKE_COMMAND} -E copy ${COMBINED_LIB_ROOT} ${COMBINED_LIB_RELEASE}
            DEPENDS cvc_base l8w8jwt miracl_core
            COMMENT "Combining all static libraries into cvc.lib using lib.exe"
    )

    # Set the library location for the target
    set(COMBINED_LIB ${COMBINED_LIB_ROOT})
else ()
    # Unix/Linux/macOS/iOS: Use ar to combine static libraries
    set(COMBINED_LIB ${CMAKE_BINARY_DIR}/libcvc.a)

    add_custom_command(
            OUTPUT ${COMBINED_LIB}
            COMMAND ${CMAKE_COMMAND} -E echo "Creating combined library..."
            COMMAND ${CMAKE_AR} -x $<TARGET_FILE:cvc_base>
            COMMAND ${CMAKE_AR} -x $<TARGET_FILE:l8w8jwt>
            COMMAND ${CMAKE_AR} -x ${MIRACL_LIB}
            COMMAND ${CMAKE_AR} -qc ${COMBINED_LIB} *.o
            COMMAND ${CMAKE_RANLIB} ${COMBINED_LIB}
            COMMAND ${CMAKE_COMMAND} -E remove *.o
            DEPENDS cvc_base l8w8jwt miracl_core
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/temp_extract
            COMMENT "Combining all static libraries into libcvc.a"
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