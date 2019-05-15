# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(receiver VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build Receiver using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

# Create executable but add no source files yet
add_executable(receiver "")

# Build in release mode by default
set(RECEIVER_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${RECEIVER_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

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

# Log4cplus
find_path(LOG4CPLUS_DIR log4cplus/logger.h)
find_library(LOG4CPLUS log4cplus)
if (NOT LOG4CPLUS_DIR OR NOT LOG4CPLUS)
    message(FATAL_ERROR "Could not find log4cplus library")
else()
    message(STATUS "log4cplus directory: ${LOG4CPLUS_DIR}")
    message(STATUS "Found log4cplus: ${LOG4CPLUS}")
endif()

# CryptoPP
find_library(CRYPTOPP cryptopp)
if (NOT CRYPTOPP)
    message(FATAL_ERROR "Could not find cryptopp library")
else()
    message(STATUS "Found cryptopp: ${CRYPTOPP}")
endif()

# Common Code
find_library(COMMON_CODE common_code HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../lib)
if (NOT COMMON_CODE)
    message(FATAL_ERROR "Could not find common_code library")
else()
    message(STATUS "Found common_code: ${COMMON_CODE}")
endif()

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

# Includes
target_include_directories(receiver PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSICommon>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSIReceiver>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../CommonCodeCLI>
    ${FLINT_DIR}/flint
    ${LOG4CPLUS_DIR}
)

# C++17
target_compile_features(receiver PUBLIC cxx_std_17)

# Add source files to executable
add_subdirectory(src)

# Link required libraries
target_link_libraries(receiver
    APSICommon::apsi_common
    APSIReceiver::apsi_receiver
    SEAL::seal
    Cuckoo::cuckoo
    stdc++fs
    ${COMMON_CODE}
    ${LOG4CPLUS}
    ${CRYPTOPP}
)
