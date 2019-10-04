# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(common_code VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build this library using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../lib)

# Create library
add_library(common_code STATIC common_utils.cpp)

# Build in release mode by default
set(APSI_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${APSI_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${common_code_SOURCE_DIR}/../cmake)

# Import APSI
if(NOT TARGET apsi_common)
    find_package(APSICommon 1.0.0 EXACT REQUIRED)
endif()

# Import SEAL
find_package(SEAL 3.3.2 EXACT REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.1.0 EXACT REQUIRED)

# Import TCLAP
find_package(TCLAP MODULE REQUIRED)

# C++17
target_compile_features(common_code PUBLIC cxx_std_17)

# Add local include directories for build
target_include_directories(common_code
    PUBLIC $<BUILD_INTERFACE:${common_code_SOURCE_DIR}>)

# Link required libraries
target_link_libraries(common_code apsi_common TCLAP)
