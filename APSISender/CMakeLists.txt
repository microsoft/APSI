# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(APSISender VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(apsi_sender STATIC "")

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

# Required files and directories
set(APSISENDER_INCLUDES_INSTALL_DIR include)
set(APSISENDER_CONFIG_IN_FILENAME ${APSISender_SOURCE_DIR}/cmake/APSISenderConfig.cmake.in)
set(APSISENDER_CONFIG_FILENAME ${APSISender_SOURCE_DIR}/cmake/APSISenderConfig.cmake)
set(APSISENDER_TARGETS_FILENAME ${APSISender_SOURCE_DIR}/cmake/APSISenderTargets.cmake)
set(APSISENDER_CONFIG_VERSION_FILENAME ${APSISender_SOURCE_DIR}/cmake/APSISenderConfigVersion.cmake)
set(APSISENDER_CONFIG_INSTALL_DIR lib/cmake/APSISender)

# Import APSICommon
find_package(APSICommon 1.0.0 EXACT REQUIRED)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Import Cuckoo library
find_package(Cuckoo 1.0 REQUIRED)

# Import FLINT library
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

# Set flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# C++17
target_compile_features(apsi_sender PUBLIC cxx_std_17)

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
target_link_libraries(apsi_sender APSICommon::apsi_common SEAL::seal Cuckoo::cuckoo ${FLINT} ${FOURQ})

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(apsi_sender
	PRIVATE $<BUILD_INTERFACE:${APSISender_SOURCE_DIR}>)

# Associate APSI to export apsi_sender_export
install(TARGETS apsi_sender EXPORT apsi_sender_export
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION ${APSISENDER_INCLUDES_INSTALL_DIR})

# Export the targets
export(EXPORT apsi_sender_export
    FILE ${APSISENDER_TARGETS_FILENAME}
    NAMESPACE APSISender::)

# Create the CMake config file
configure_file(${APSISENDER_CONFIG_IN_FILENAME} ${APSISENDER_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT apsi_sender_export
    FILE APSISenderTargets.cmake
    NAMESPACE APSISender::
    DESTINATION ${APSISENDER_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${APSISENDER_CONFIG_VERSION_FILENAME}
    VERSION ${APSISENDER_VERSION}
    COMPATIBILITY ExactVersion)

# Install other files 
install(
    FILES
        ${APSISENDER_CONFIG_FILENAME}
        ${APSISENDER_CONFIG_VERSION_FILENAME}
    DESTINATION ${APSISENDER_CONFIG_INSTALL_DIR})
