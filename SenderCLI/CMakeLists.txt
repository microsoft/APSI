# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(sender VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build Sender using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

# Create executable but add no source files yet
add_executable(sender "")

# Build in release mode by default
set(SENDER_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${SENDER_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${sender_SOURCE_DIR}/../cmake)

# Import APSICommon
find_package(APSICommon 1.0.0 EXACT REQUIRED)

# Import APSISender
find_package(APSISender 1.0.0 EXACT REQUIRED)

# Import SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.1.0 EXACT REQUIRED)

# Import GMP
find_package(GMP MODULE REQUIRED)

# Import Flint
find_package(Flint MODULE REQUIRED)

# Import ZeroMQ
find_package(ZeroMQ MODULE REQUIRED)

# Import ZeroMQpp
find_package(ZeroMQpp MODULE REQUIRED)

# Import FourQ
find_package(FourQ MODULE REQUIRED)

# Import Log4cplus 
find_package(Log4cplus MODULE REQUIRED)

# Import TCLAP
find_package(TCLAP MODULE REQUIRED)

# Add common_code
find_path(COMMON_CODE_INCLUDE_DIR
    NAMES base_clp.h common_utils.h
    HINTS ${sender_SOURCE_DIR}/../CommonCodeCLI)
find_library(COMMON_CODE_LIBRARY_PATH
    NAMES common_code
    HINTS ${sender_SOURCE_DIR}/../lib)
add_library(common_code UNKNOWN IMPORTED)
set_target_properties(common_code PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${COMMON_CODE_INCLUDE_DIR}
    IMPORTED_LOCATION ${COMMON_CODE_LIBRARY_PATH}) 

# C++17
target_compile_features(sender PUBLIC cxx_std_17)

# Require -maes flag
target_compile_options(sender PRIVATE
    "-march=native")

# Link required libraries
target_link_libraries(sender
    APSICommon::apsi_common
    APSISender::apsi_sender
    stdc++fs
    common_code
)

# Add source files to executable
add_subdirectory(src)
