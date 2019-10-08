# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(receiver VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build Receiver using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${receiver_SOURCE_DIR}/../bin)

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

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${receiver_SOURCE_DIR}/../cmake)

# Import APSICommon
if(NOT TARGET apsi_common)
    find_package(APSICommon 1.0.0 EXACT REQUIRED)
endif()

# Import APSIReceiver
if(NOT TARGET apsi_receiver)
    find_package(APSIReceiver 1.0.0 EXACT REQUIRED)
endif()

# Import SEAL
find_package(SEAL 3.4.0 EXACT REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.0.0 EXACT REQUIRED)

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

# Import TCLAP
if(TCLAP_ROOT)
    unset(TCLAP_INCLUDE_DIR CACHE)
endif()
find_package(TCLAP MODULE REQUIRED)

# Add common_code
if(NOT TARGET common_code)
    find_path(COMMON_CODE_INCLUDE_DIR
        NAMES base_clp.h common_utils.h
        HINTS ${receiver_SOURCE_DIR}/../CommonCodeCLI)
    find_library(COMMON_CODE_LIBRARY_PATH
        NAMES common_code
        HINTS ${receiver_SOURCE_DIR}/../lib)
    add_library(common_code UNKNOWN IMPORTED)
    set_target_properties(common_code PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${COMMON_CODE_INCLUDE_DIR}
        IMPORTED_LOCATION ${COMMON_CODE_LIBRARY_PATH}) 
endif()

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
    apsi_common
    apsi_receiver
    stdc++fs
    common_code
)
