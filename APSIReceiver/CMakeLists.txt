# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(APSIReceiver VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(apsi_receiver STATIC "")
set_property(TARGET apsi_receiver PROPERTY POSITION_INDEPENDENT_CODE ON)

# Build in release mode by default
set(APSI_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${APSI_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# In Debug mode enable also APSI_DEBUG by default
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(APSI_DEBUG_DEFAULT ON)
else()
    set(APSI_DEBUG_DEFAULT OFF)
endif()
set(APSI_DEBUG ${APSI_DEBUG_DEFAULT})

# Required files and directories
set(APSIRECEIVER_INCLUDES_INSTALL_DIR include)
set(APSIRECEIVER_CONFIG_IN_FILENAME ${APSIReceiver_SOURCE_DIR}/cmake/APSIReceiverConfig.cmake.in)
set(APSIRECEIVER_CONFIG_FILENAME ${APSIReceiver_SOURCE_DIR}/cmake/APSIReceiverConfig.cmake)
set(APSIRECEIVER_TARGETS_FILENAME ${APSIReceiver_SOURCE_DIR}/cmake/APSIReceiverTargets.cmake)
set(APSIRECEIVER_CONFIG_VERSION_FILENAME ${APSIReceiver_SOURCE_DIR}/cmake/APSIReceiverConfigVersion.cmake)
set(APSIRECEIVER_CONFIG_INSTALL_DIR lib/cmake/APSIReceiver)

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${APSIReceiver_SOURCE_DIR}/../cmake)

# Import APSICommon
find_package(APSICommon 1.0.0 EXACT REQUIRED)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.1.0 REQUIRED)

# Import FourQ
find_package(FourQ MODULE REQUIRED)

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# C++17
target_compile_features(apsi_receiver PUBLIC cxx_std_17)

# Defines
add_definitions(-DHAVE_CONFIG)
add_definitions(-DUSE_SECURE_SEED)
add_definitions(-DNDEBUG)
add_definitions(-D_AMD64_)
add_definitions(-D_AVX2_)
add_definitions(-D_ASM_)
add_definitions(-D__LINUX__)

# Link required libraries
target_link_libraries(apsi_receiver APSICommon::apsi_common)

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(apsi_receiver
	PRIVATE $<BUILD_INTERFACE:${APSIReceiver_SOURCE_DIR}>)

# Associate APSI to export apsi_receiver_export
install(TARGETS apsi_receiver EXPORT apsi_receiver_export
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION ${APSIRECEIVER_INCLUDES_INSTALL_DIR})

# Export the targets
export(EXPORT apsi_receiver_export
    FILE ${APSIRECEIVER_TARGETS_FILENAME}
    NAMESPACE APSIReceiver::)

# Create the CMake config file
configure_file(${APSIRECEIVER_CONFIG_IN_FILENAME} ${APSIRECEIVER_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT apsi_receiver_export
    FILE APSIReceiverTargets.cmake
    NAMESPACE APSIReceiver::
    DESTINATION ${APSIRECEIVER_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${APSIRECEIVER_CONFIG_VERSION_FILENAME}
    VERSION ${APSIReceiver_VERSION}
    COMPATIBILITY ExactVersion)

# Install other files 
install(
    FILES
        ${APSIRECEIVER_CONFIG_FILENAME}
        ${APSIRECEIVER_CONFIG_VERSION_FILENAME}
    DESTINATION ${APSIRECEIVER_CONFIG_INSTALL_DIR})
