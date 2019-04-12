# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(unit_tests VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build Unit Tests using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

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

# Import APSI
find_package(APSI 1.0.0 EXACT REQUIRED)

# Import SEAL
find_package(SEAL 3.2.0 REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.0 REQUIRED)

# FLINT library
find_path(FLINT_DIR NAMES flint/fmpz.h)
find_library(FLINT flint)
if (NOT FLINT OR NOT FLINT_DIR)
    message(FATAL_ERROR "Could not find FLINT library")
else()
    message(STATUS "Flint directory: ${FLINT_DIR}")
    message(STATUS "Found FLINT: ${FLINT}")
endif()

# FourQ
find_path(FOURQ_DIR NAMES FourQ/FourQ.h)
find_library(FOURQ FourQ)
if (NOT FOURQ OR NOT FOURQ_DIR)
    message(FATAL_ERROR "Could not find FourQ library")
else()
    message(STATUS "FourQ directory: ${FOURQ_DIR}")
    message(STATUS "Found FourQ: ${FOURQ}")
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

# ZeroMQ
find_path(ZMQ_DIR zmqpp/zmqpp.hpp)
find_library(ZMQ zmq)
find_library(ZMQPP zmqpp)
if (NOT ZMQ OR NOT ZMQPP OR NOT ZMQ_DIR)
    message(FATAL_ERROR "Could not find zmq or zmqpp libraries")
else()
    message(STATUS "zmqpp directory:  ${ZMQ_DIR}")
    message(STATUS "Found zmq: ${ZMQ}")
    message(STATUS "Found zmqpp: ${ZMQPP}")
endif()

# GMP
find_library(GMP gmp)
if (NOT GMP)
    message(FATAL_ERROR "Could not find gmp library")
else()
    message(STATUS "Found gmp: ${GMP}")
endif()

# CryptoPP
find_library(CRYPTOPP cryptopp)
if (NOT CRYPTOPP)
    message(FATAL_ERROR "Could not find cryptopp library")
else()
    message(STATUS "Found cryptopp: ${CRYPTOPP}")
endif()

# Google Test
find_path(GTEST_DIR gtest/gtest.h)
find_library(GTEST gtest)
if (NOT GTEST OR NOT GTEST_DIR)
    message(FATAL_ERROR "Could not find Google Test library")
else()
    message(STATUS "Google Test directory: ${GTEST_DIR}")
    message(STATUS "Found Google Test: ${GTEST}")
endif()

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

# Includes
target_include_directories(unit_tests PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../APSI>
    ${FLINT_DIR}/flint
    ${LOG4CPLUS_DIR}
    ${FOURQ_DIR}/FourQ
)

# C++17
target_compile_features(unit_tests PUBLIC cxx_std_17)

# Defines
add_definitions(-D_AMD64_)
add_definitions(-D_AVX2_)
add_definitions(-D_ASM_)
add_definitions(-D__LINUX__)

# Link required libraries
target_link_libraries(unit_tests
    APSI::apsi
    ${FLINT}
    ${ZMQ}
    ${ZMQPP}
    ${GMP}
    ${LOG4CPLUS}
    ${CRYPTOPP}
    ${GTEST}
    ${FOURQ}
    stdc++fs
)

# Add source files to executable
add_subdirectory(src)
