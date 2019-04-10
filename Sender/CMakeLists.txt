# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(sender VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Executable will be in ../bin
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

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

# Import APSI
find_package(APSI 1.0.0 EXACT REQUIRED)

# Set flags
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

# C++17
target_compile_features(apsi PUBLIC cxx_std_17)

# Defines
#add_definitions(-DHAVE_CONFIG)
#add_definitions(-DUSE_SECURE_SEED)
#add_definitions(-DNDEBUG)
#add_definitions(-D_AMD64_)
#add_definitions(-D_AVX2_)
#add_definitions(-D_ASM_)
#add_definitions(-D__LINUX__)

# Link required libraries
target_link_libraries(sender APSI::apsi)

# Add source files to executable
add_subdirectory(src)

