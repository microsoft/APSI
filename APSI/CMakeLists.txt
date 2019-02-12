# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(APSI VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Library will be in ../lib
set(CMAKE_LIBARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

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

# Link Microsoft SEAL
target_link_libraries(apsi SEAL::seal)

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(apsi
	PRIVATE $<BUILD_INTERFACE:${APSI_SOURCE_DIR}>)

# Install the library
#install(TARGETS apsi LIBRARY DESTINATION lib)

