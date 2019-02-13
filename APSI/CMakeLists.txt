# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(APSI VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(apsi STATIC "")

# Build in release mode by default
set(APSI_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${APSI_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import Cuckoo library
find_package(Cuckoo 1.0 REQUIRED)

# Import FLINT library
find_path(FLINT_DIR NAMES flint/fmpz.h)
find_library(FLINT flint)
if (NOT FLINT)
    message(FATAL_ERROR "Could not find FLINT library")
else()
    message(STATUS "Flint directory: ${FLINT_DIR}")
    message(STATUS "Found FLINT: ${FLINT}")
endif()

# FourQ
find_path(FOURQ_DIR NAMES FourQ/FourQ.h)
find_library(FOURQ FourQ)
if (NOT FOURQ)
    message(FATAL_ERROR "Could not find FourQ library")
else()
    message(STATUS "FourQ directory: ${FOURQ_DIR}")
    message(STATUS "Found FourQ: ${FOURQ}")
endif()

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# C++17
target_compile_features(apsi PUBLIC cxx_std_17)

# Defines
add_definitions(-DHAVE_CONFIG)
add_definitions(-DUSE_SECURE_SEED)
add_definitions(-DNDEBUG)
add_definitions(-D_AMD64_)
add_definitions(-D_AVX2_)
add_definitions(-D_ASM_)
add_definitions(-D__LINUX__)

# Includes
include_directories(${FLINT_DIR}/flint)
include_directories(${FOURQ_DIR}/FourQ)

# Link required libraries
target_link_libraries(apsi SEAL::seal Cuckoo::cuckoo ${FLINT} ${FOURQ})

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(apsi
	PRIVATE $<BUILD_INTERFACE:${APSI_SOURCE_DIR}>)

# Install the library
#install(TARGETS apsi LIBRARY DESTINATION lib)

