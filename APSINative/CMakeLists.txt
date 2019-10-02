# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(apsinative VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(apsinative SHARED "")
set_property(TARGET apsinative PROPERTY POSITION_INDEPENDENT_CODE ON)

# Import APSICommon
find_package(APSICommon 1.0.0 EXACT REQUIRED)

# Import APSIReceiver
find_package(APSIReceiver 1.0.0 EXACT REQUIRED)

# Import SEAL
find_package(SEAL 3.2.0 REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.0 REQUIRED)

# Import FLINT library
find_path(FLINT_DIR NAMES flint/fmpz.h)
if (NOT FLINT_DIR)
    message(FATAL_ERROR "Could not find FLINT library")
else()
    message(STATUS "Flint directory: ${FLINT_DIR}")
endif()

# Includes
target_include_directories(apsinative PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSICommon>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSIReceiver>
    ${FLINT_DIR}/flint
)

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

# C++17
target_compile_features(apsinative PUBLIC cxx_std_17)

# Add source files to library
target_sources(apsinative
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/apsinative.cpp
)

# Link required libraries
target_link_libraries(apsinative
    APSICommon::apsi_common
    APSIReceiver::apsi_receiver
    SEAL::seal
    Cuckoo::cuckoo
)
