# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(APSICommon VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(apsi_common STATIC "")
set_property(TARGET apsi_common PROPERTY POSITION_INDEPENDENT_CODE ON)

# Build in release mode by default
set(APSI_DEFAULT_BUILD_TYPE "Release")
if(NOT CMAKE_BUILD_TYPE)
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
set(APSICOMMON_INCLUDES_INSTALL_DIR include)
set(APSICOMMON_CONFIG_IN_FILENAME ${APSICommon_SOURCE_DIR}/cmake/APSICommonConfig.cmake.in)
set(APSICOMMON_CONFIG_FILENAME ${APSICommon_SOURCE_DIR}/cmake/APSICommonConfig.cmake)
set(APSICOMMON_TARGETS_FILENAME ${APSICommon_SOURCE_DIR}/cmake/APSICommonTargets.cmake)
set(APSICOMMON_CONFIG_VERSION_FILENAME ${APSICommon_SOURCE_DIR}/cmake/APSICommonConfigVersion.cmake)
set(APSICOMMON_CONFIG_INSTALL_DIR lib/cmake/APSICommon)

# For extra modules
list(APPEND CMAKE_MODULE_PATH ${APSICommon_SOURCE_DIR}/../cmake)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import Cuckoo
find_package(Cuckoo 1.1.0 EXACT REQUIRED)

# Import Microsoft GSL
find_package(msgsl MODULE REQUIRED)

# Import ZeroMQ
find_package(ZeroMQ MODULE REQUIRED)

# Import ZeroMQpp
find_package(ZeroMQpp MODULE REQUIRED)

# Import FourQ
find_package(FourQ MODULE REQUIRED)

# Import Log4cplus
find_package(Log4cplus MODULE REQUIRED)

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# C++17
target_compile_features(apsi_common PUBLIC cxx_std_17)

# Defines
add_definitions(-DHAVE_CONFIG)
add_definitions(-DUSE_SECURE_SEED)
add_definitions(-DNDEBUG)
add_definitions(-D_AMD64_)
add_definitions(-D_AVX2_)
add_definitions(-D_ASM_)
add_definitions(-D__LINUX__)

# Link required libraries
target_link_libraries(apsi_common PUBLIC
    SEAL::seal
    msgsl
    Cuckoo::cuckoo
    ZeroMQ
    ZeroMQpp
    FourQ
    Log4cplus)

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(apsi_common
	PUBLIC $<BUILD_INTERFACE:${APSICommon_SOURCE_DIR}>)

# Associate APSI to export apsi_export
install(TARGETS apsi_common EXPORT apsi_common_export
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION ${APSICOMMON_INCLUDES_INSTALL_DIR})

# Associate Microsoft GSL to apsi_common_export
install(TARGETS msgsl EXPORT apsi_common_export)

# Export the targets
export(EXPORT apsi_common_export
    FILE ${APSICOMMON_TARGETS_FILENAME}
    NAMESPACE APSICommon::)

# Create the CMake config file
configure_file(${APSICOMMON_CONFIG_IN_FILENAME} ${APSICOMMON_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT apsi_common_export
    FILE APSICommonTargets.cmake
    NAMESPACE APSICommon::
    DESTINATION ${APSICOMMON_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${APSICOMMON_CONFIG_VERSION_FILENAME}
    VERSION ${APSICommon_VERSION}
    COMPATIBILITY ExactVersion)

# Install other files 
install(
    FILES
        ${APSICOMMON_CONFIG_FILENAME}
        ${APSICOMMON_CONFIG_VERSION_FILENAME}
    DESTINATION ${APSICOMMON_CONFIG_INSTALL_DIR})
