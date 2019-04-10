# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(common_code VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build this library using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

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

# Set flags
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# Add APSI
find_package(APSI 1.0.0 EXACT REQUIRED)

# Add SEAL
find_package(SEAL 3.2.0 REQUIRED)

# Add Cuckoo
find_package(Cuckoo 1.0 REQUIRED)

# C++17
target_compile_features(common_code PUBLIC cxx_std_17)

# Defines
#add_definitions(-DHAVE_CONFIG)
#add_definitions(-DUSE_SECURE_SEED)
#add_definitions(-DNDEBUG)
#add_definitions(-D_AMD64_)
#add_definitions(-D_AVX2_)
#add_definitions(-D_ASM_)
#add_definitions(-D__LINUX__)

target_include_directories(common_code PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSI>
)

# Link required libraries
target_link_libraries(common_code APSI::apsi SEAL::seal Cuckoo::cuckoo)

# Add source files to library
#add_subdirectory(apsi)

# Add local include directories for build
#target_include_directories(apsi
#	PRIVATE $<BUILD_INTERFACE:${APSI_SOURCE_DIR}>)

