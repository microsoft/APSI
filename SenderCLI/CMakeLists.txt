# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(sender VERSION 1.0.0 LANGUAGES CXX C)

if(MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Build in release mode by default
set(DEFAULT_BUILD_TYPE "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${DEFAULT_BUILD_TYPE} CACHE
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
message(STATUS "${PROJECT_NAME} set APSI debug mode: ${APSI_DEBUG}")

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../bin)

# Imports 
find_package(APSISender 1.0.0 EXACT REQUIRED)
find_package(CommonCLI 1.0.0 EXACT REQUIRED)

# Create executable but add no source files yet
add_executable(sender "")

# Add source files to executable
add_subdirectory(src)

# Link required libraries
target_link_libraries(sender
    APSI::Sender
    APSI::CommonCLI
    stdc++fs
)
