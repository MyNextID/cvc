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

set(CVC_MAJOR 1)
set(CVC_MINOR 0)
set(CVC_PATCH 0)
set(CVC_VERSION_STRING "${CVC_MAJOR}.${CVC_MINOR}.${CVC_PATCH}")

# Set output directories to build folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

# Build miracl-core library
execute_process(
        COMMAND python3 config64.py -o 3 -o 1
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
        RESULT_VARIABLE MIRACL_BUILD_RESULT
)

if (NOT MIRACL_BUILD_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to build miracl-core library")
endif ()

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
        PUBLIC
        ${CMAKE_SOURCE_DIR}/libs/miracl-core/c/core.a
        l8w8jwt
)

# Include directories for header access
target_include_directories(cvc
        PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/libs/miracl-core/c
        ${CMAKE_SOURCE_DIR}/libs/l8w8jwt/include
)