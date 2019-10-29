# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(unit_tests VERSION 1.0.0 LANGUAGES CXX C)

if(MSVC)
    message(FATAL_ERROR "Please build Unit Tests using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../bin)

# Create executable but add no source files yet
add_executable(unit_tests "")

# Build in release mode by default
set(UNIT_TESTS_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${UNIT_TESTS_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${unit_tests_SOURCE_DIR}/../cmake)

# For locating local build of APSICommon config
list(APPEND CMAKE_PREFIX_PATH ${PROJECT_SOURCE_DIR}/../APSICommon/cmake)

# For locating local build of APSISender config
list(APPEND CMAKE_PREFIX_PATH ${PROJECT_SOURCE_DIR}/../APSISender/cmake)

# For locating local build of APSIReceiver config
list(APPEND CMAKE_PREFIX_PATH ${PROJECT_SOURCE_DIR}/../APSIReceiver/cmake)

# Import APSI
find_package(APSISender 1.0.0 EXACT REQUIRED
    PATHS ${PROJECT_SOURCE_DIR}/../APSISender/cmake
)
find_package(APSIReceiver 1.0.0 EXACT REQUIRED
    PATHS ${PROJECT_SOURCE_DIR}/../APSIReceiver/cmake
)

if(NOT TARGET gtest)
    message(FATAL_ERROR "Target `gtest` not found. Please use the top-level CMake file.")
endif()

# Link required libraries
target_link_libraries(unit_tests
    APSI::Common
    APSI::Sender
    APSI::Receiver
    gtest
    stdc++fs
)

# Add source files to executable
add_subdirectory(src)
