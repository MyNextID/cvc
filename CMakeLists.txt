#  Copyright 2025 Peter Paravinja

cmake_minimum_required(VERSION 3.19)
project(cvc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(CVC_MAJOR 2)
set(CVC_MINOR 5)
set(CVC_PATCH 0)
set(CVC_VERSION_STRING "${CVC_MAJOR}.${CVC_MINOR}.${CVC_PATCH}")

# Build miracl-core library
execute_process(
        COMMAND python3 config64.py -o 3
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
        RESULT_VARIABLE MIRACL_BUILD_RESULT
)

if(NOT MIRACL_BUILD_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to build miracl-core library")
endif()

# Add l8w8jwt subdirectory and build as static library
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum CMake policy version" FORCE)
add_subdirectory(libs/l8w8jwt)

# Create main library
add_library(cvc STATIC
        # source files
        src/crypto.c
)

# Link libraries
target_link_libraries(cvc
        PRIVATE
        ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a
        l8w8jwt
)

# Include directories for header access
target_include_directories(cvc
        PRIVATE
        ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
        ${CMAKE_SOURCE_DIR}/libs/l8w8jwt/include
)