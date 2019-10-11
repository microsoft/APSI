# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(unit_tests VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build Unit Tests using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../bin)

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

# Import APSICommon
if(NOT TARGET apsi_common)
    find_package(APSICommon 1.0.0 EXACT REQUIRED)
endif()

# Import APSISender
if(NOT TARGET apsi_sender)
    find_package(APSISender 1.0.0 EXACT REQUIRED)
endif()

# Import APSIReceiver
if(NOT TARGET apsi_receiver)
    find_package(APSIReceiver 1.0.0 EXACT REQUIRED)
endif()

# Import SEAL
find_package(SEAL 3.4.0 REQUIRED)

# Import Kuku
find_package(Kuku 1.0.0 REQUIRED)

# Import ZeroMQ
if(ZeroMQ_ROOT)
    unset(ZEROMQ_INCLUDE_DIR CACHE)
    unset(ZEROMQ_LIBRARY_DIR CACHE)
    unset(ZEROMQ_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQ MODULE REQUIRED)

# Import ZeroMQpp
if(ZeroMQpp_ROOT)
    unset(ZEROMQPP_INCLUDE_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQpp MODULE REQUIRED)

# Import FourQ
if(FourQ_ROOT)
    unset(FOURQ_INCLUDE_DIR CACHE)
    unset(FOURQ_LIBRARY_DIR CACHE)
    unset(FOURQ_LIBRARY_PATH CACHE)
endif()
find_package(FourQ MODULE REQUIRED)

# Import Log4cplus
if(Log4cplus_ROOT)
    unset(LOG4CPLUS_INCLUDE_DIR CACHE)
    unset(LOG4CPLUS_LIBRARY_DIR CACHE)
    unset(LOG4CPLUS_LIBRARY_PATH CACHE)
endif()
find_package(Log4cplus MODULE REQUIRED)

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

# C++17
target_compile_features(unit_tests PUBLIC cxx_std_17)

# Defines
add_definitions(-D_AMD64_)
add_definitions(-D_AVX2_)
add_definitions(-D_ASM_)
add_definitions(-D__LINUX__)

# Link required libraries
target_link_libraries(unit_tests
    apsi_common
    apsi_sender
    apsi_receiver
    gtest
    stdc++fs
)

# Add source files to executable
add_subdirectory(src)
