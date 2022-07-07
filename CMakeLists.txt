# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

###################################################
# Project APSI includes the following components: #
#   1. APSI C++ library that includes             #
#      1) common API                              #
#      2) sender API                              #
#      3) receiver API                            #
#   2. APSI unit tests                            #
#   3. APSI integration tests                     #
#   4. APSI command line interface                #
###################################################

# [option] CMAKE_BUILD_TYPE (default: "Release")
# Build in one of the following modes: Release, Debug, MiniSizeRel, or RelWithDebInfo.
# Most generators recognize these and can set the compiler flags accordingly. We set
# the build type here before creating the project to prevent the CMake generator from
# overriding our default of "Release".
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

project(APSI VERSION 0.8.2 LANGUAGES CXX C)

# This policy was introduced in CMake 3.13; OLD by default until CMake 3.21
cmake_policy(SET CMP0077 NEW)

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceRuns)
include(CheckLanguage)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(APSIMacros)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

# In Debug mode, define APSI_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(APSI_DEBUG ON)
    # In Debug mode, enable extra compiler flags.
    include(EnableCXXCompilerFlags)
else()
    set(APSI_DEBUG OFF)
endif()
message(STATUS "APSI debug mode: ${APSI_DEBUG}")

# [option] APSI_USE_CXX17_OPTION_STR (default: ON)
# Use C++17, use C++14 otherwise. An error will be thrown if SEAL_USE_CXX17 is ON but APSI_USE_CXX17 is OFF.
set(APSI_USE_CXX17_OPTION_STR "Use C++17")
option(APSI_USE_CXX17 ${APSI_USE_CXX17_OPTION_STR} ON)
message(STATUS "APSI_USE_CXX17: ${APSI_USE_CXX17}")

# Enable security-related compile options (MSVC only)
set(APSI_SECURE_COMPILE_OPTIONS_OPTION_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(APSI_SECURE_COMPILE_OPTIONS ${APSI_SECURE_COMPILE_OPTIONS_OPTION_STR} OFF)
mark_as_advanced(APSI_SECURE_COMPILE_OPTIONS)

# Enable AVX detection
set(APSI_DETECT_AVX_OPTION_STR "Detect the presence of AVX/AVX2 extensions")
option(APSI_DETECT_AVX ${APSI_DETECT_AVX_OPTION_STR} ON)
mark_as_advanced(APSI_DETECT_AVX)

# Path for output
set(OUTLIB_PATH "lib")

# Required files and directories
include(GNUInstallDirs)

# Source tree
set(APSI_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/APSIConfig.cmake.in)
set(APSI_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR})
set(APSI_CONFIG_H_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/common/apsi/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(APSI_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(APSI_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSITargets.cmake)
set(APSI_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSIConfig.cmake)
set(APSI_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSIConfigVersion.cmake)
set(APSI_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/common/apsi/config.h)

# Install
set(APSI_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
set(APSI_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})

# pkg-config
# TODO: not provided yet

#########################
# External Dependencies #
#########################
# All dependencies are assumed pre-installed.
# find_package might throw a FATAL_ERROR before"xxx: not found", e.g. with vcpkg.cmake.

# Microsoft SEAL
find_package(SEAL 3.7 QUIET REQUIRED)
if(NOT SEAL_FOUND)
    message(FATAL_ERROR "Microsoft SEAL: not found")
else()
    message(STATUS "Microsoft SEAL: found")
endif()
if(NOT APSI_USE_CXX17 AND SEAL_USE_CXX17)
    message(FATAL_ERROR "CXX standards mismatch: APSI_USE_CXX17 is OFF, SEAL_USE_CXX17 is ON")
endif()

# Microsoft Kuku
find_package(Kuku 2.1 QUIET REQUIRED)
if(NOT Kuku_FOUND)
    message(FATAL_ERROR "Microsoft Kuku: not found")
else()
    message(STATUS "Microsoft Kuku: found")
endif()

# Flatbuffers
find_package(Flatbuffers REQUIRED)
if(NOT Flatbuffers_FOUND)
    message(FATAL_ERROR "Flatbuffers: not found")
else()
    message(STATUS "Flatbuffers: found")
    get_target_property(FLATBUFFERS_FLATC_PATH flatbuffers::flatc IMPORTED_LOCATION_RELEASE)
    message(STATUS "flatc path: ${FLATBUFFERS_FLATC_PATH}")
    include(CompileSchemaCXX)
endif()

# jsoncpp: for parameter configuration
find_package(jsoncpp REQUIRED)
if (NOT jsoncpp_FOUND)
    message(FATAL_ERROR "jsoncpp: not found")
else()
    message(STATUS "jsoncpp: found")
endif()

# [Option] APSI_USE_LOG4CPLUS (default: ON)
set(APSI_USE_LOG4CPLUS_OPTION_STR "Use Log4cplus for logging")
option(APSI_USE_LOG4CPLUS ${APSI_USE_LOG4CPLUS_OPTION_STR} ON)
if(APSI_USE_LOG4CPLUS)
    # Log4cplus
    find_package(log4cplus REQUIRED)
    if(NOT log4cplus_FOUND)
        message(FATAL_ERROR "log4cplus: not found")
    else()
        message(STATUS "log4cplus: found")
    endif()
endif()

# [Option] APSI_USE_ZMQ (default: ON)
set(APSI_USE_ZMQ_OPTION_STR "Use ZeroMQ for networking")
option(APSI_USE_ZMQ ${APSI_USE_ZMQ_OPTION_STR} ON)
if(APSI_USE_ZMQ)
    # ZeroMQ base
    find_package(ZeroMQ REQUIRED)
    if(NOT ZeroMQ_FOUND)
        message(FATAL_ERROR "ZeroMQ: not found")
    else()
        message(STATUS "ZeroMQ: found")
    endif()
    # cppzmq wrapper
    find_package(cppzmq REQUIRED)
    if(NOT cppzmq_FOUND)
        message(FATAL_ERROR "cppzmq: not found")
    else()
        message(STATUS "cppzmq: found")
    endif()
endif()

# [Option] APSI_BUILD_TESTS (default: OFF)
set(APSI_BUILD_TESTS_OPTION_STR "Build unit and integration tests for APSI")
option(APSI_BUILD_TESTS ${APSI_BUILD_TESTS_OPTION_STR} OFF)
if(APSI_BUILD_TESTS)
    # Google Test
    find_package(GTest CONFIG REQUIRED)
    if(NOT GTest_FOUND)
        message(FATAL_ERROR "GTest: not found")
    else()
        message(STATUS "GTest: found")
    endif()
endif()

# [Option] APSI_BUILD_CLI (default: OFF)
set(APSI_BUILD_CLI_OPTION_STR "Build example command line interface applications")
cmake_dependent_option(APSI_BUILD_CLI ${APSI_BUILD_CLI_OPTION_STR} OFF "APSI_USE_ZMQ;APSI_USE_LOG4CPLUS" OFF)
if (APSI_BUILD_CLI)
    # TCLAP
    find_path(TCLAP_INCLUDE_DIRS "tclap/Arg.h")
    if(TCLAP_INCLUDE_DIRS STREQUAL "TCLAP_INCLUDE_DIRS-NOTFOUND")
        message(FATAL_ERROR "TCLAP: not found")
    else()
        message(STATUS "TCLAP: found")
        message(STATUS "TCLAP_INCLUDE_DIRS: ${TCLAP_INCLUDE_DIRS}")
    endif()
endif()

####################
# APSI C++ library #
####################

# [option] BUILD_SHARED_LIBS (default: OFF)
# Build a shared library if set to ON. Build a static library regardlessly.
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
# TODO: consider building shared in future
if(BUILD_SHARED_LIBS)
    message(FATAL_ERROR "Only static build is supported; set `BUILD_SHARED_LIBS=OFF`")
endif()

# Create the config file
configure_file(${APSI_CONFIG_H_IN_FILENAME} ${APSI_CONFIG_H_FILENAME})
install(
    FILES ${APSI_CONFIG_H_FILENAME}
    DESTINATION ${APSI_INCLUDES_INSTALL_DIR}/apsi)

# Create a single library "apsi" for common, sender, and receiver
add_library(apsi STATIC)
apsi_set_version_filename(apsi)
apsi_set_language(apsi)
target_include_directories(apsi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/common>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
target_include_directories(apsi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/sender>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
target_include_directories(apsi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/receiver>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
target_include_directories(apsi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
target_include_directories(apsi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/sender>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_set_version(apsi)
apsi_link_threads(apsi)
apsi_install_target(apsi APSITargets)

target_link_libraries(apsi
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
if(APSI_USE_LOG4CPLUS)
    target_link_libraries(apsi PUBLIC log4cplus::log4cplus)
endif()
if(APSI_USE_ZMQ)
    target_link_libraries(apsi PUBLIC libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(apsi PUBLIC -DHAVE_CONFIG)
target_compile_options(apsi PUBLIC -DUSE_SECURE_SEED)
target_compile_options(apsi PUBLIC -DUSE_ENDO=true)

# Set system
if(MSVC)
    target_compile_options(apsi PUBLIC -D__WINDOWS__)
elseif (UNIX)
    target_compile_options(apsi PUBLIC -D__LINUX__)
endif()

# Set architecture
include(DetectArch)
if(APSI_FOURQ_ARM64)
    # _ARM64_ needs to be set whether the ARM64 optimizations are used
    # (in UNIX) or the generic implementation is used (Windows)
    target_compile_options(apsi PUBLIC -D_ARM64_)
endif()
message(STATUS "${CMAKE_SYSTEM_PROCESSOR} is the processor")
if(CMAKE_SYSTEM_PROCESSOR STREQUAL X86)
    target_compile_options(apsi PUBLIC -D_X86_)
endif()

if(APSI_FOURQ_AMD64)
    target_compile_options(apsi PUBLIC -D_AMD64_)
    message(STATUS "FourQlib optimization: arch=AMD64")
elseif (APSI_FOURQ_ARM64 AND UNIX)
    message(STATUS "FourQlib optimization: arch=ARM64")
else()
    target_compile_options(apsi PUBLIC -D_GENERIC_)
    message(STATUS "FourQlib optimization: arch=GENERIC")
endif()

# Set AVX or AVX2 if not generic
if(APSI_FOURQ_AMD64 AND APSI_DETECT_AVX)
    include(FindAVX)
    check_for_avx(apsi)
    if (HAVE_AVX2_EXTENSIONS)
        target_compile_options(apsi PUBLIC -D_AVX2_)
        message(STATUS "FourQlib optimization: simd=AVX2")
    elseif(HAVE_AVX_EXTENSIONS)
        target_compile_options(apsi PUBLIC -D_AVX_)
        message(STATUS "FourQlib optimization: simd=AVX")
    endif()
else()
    message(STATUS "FourQlib optimization: simd=OFF")
endif()

# Use optimized assembly on Linux (non-AVX or AVX2)
set(APSI_FOURQ_USE_ASM OFF)
if(UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
    check_language(ASM)
    if(CMAKE_ASM_COMPILER)
        enable_language(ASM)
        target_compile_options(apsi PUBLIC -D_ASM_)
        set(APSI_FOURQ_USE_ASM ON)
        message(STATUS "FourQlib optimization: asm=ON")
    endif()
endif()

# Add source files to library and header files to install
# Must follow configurations for FourQlib
set(APSI_SOURCE_FILES "")
add_subdirectory(common/apsi)
add_subdirectory(receiver/apsi)
add_subdirectory(sender/apsi)

target_sources(apsi PRIVATE ${APSI_SOURCE_FILES})

#################################
# Installation and CMake config #
#################################

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${APSI_CONFIG_IN_FILENAME} ${APSI_CONFIG_FILENAME}
    INSTALL_DESTINATION ${APSI_CONFIG_INSTALL_DIR}
)

# Install the export
install(
    EXPORT APSITargets
    NAMESPACE APSI::
    DESTINATION ${APSI_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${APSI_CONFIG_VERSION_FILENAME}
    VERSION ${APSI_VERSION}
    COMPATIBILITY SameMinorVersion)

# Install config and module files
install(
    FILES
        ${APSI_CONFIG_FILENAME}
        ${APSI_CONFIG_VERSION_FILENAME}
    DESTINATION ${APSI_CONFIG_INSTALL_DIR})

# We export SEALTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT APSITargets
    NAMESPACE APSI::
    FILE ${APSI_TARGETS_FILENAME})

###################
# APSI unit tests #
###################

if(APSI_BUILD_TESTS)
    add_executable(unit_tests)
    add_subdirectory(tests/unit/src)
    target_link_libraries(unit_tests apsi GTest::gtest)
endif()

##########################
# APSI integration tests #
##########################

if(APSI_BUILD_TESTS)
    add_executable(integration_tests)
    add_subdirectory(tests/integration/src)
    target_link_libraries(integration_tests apsi GTest::gtest)
endif()

##########################
# Command Line Interface #
##########################

if(APSI_BUILD_CLI)
    add_library(common_cli OBJECT)
    add_subdirectory(cli/common)
    target_include_directories(common_cli PUBLIC cli)
    target_include_directories(common_cli PUBLIC ${TCLAP_INCLUDE_DIRS})
    target_link_libraries(common_cli PUBLIC apsi)
    if (NOT MSVC AND NOT APPLE)
        target_link_libraries(common_cli PUBLIC stdc++fs)
    endif()
    if(NOT APSI_USE_CXX17)
        message(STATUS "Command line interface is built with C++17 regardless of APSI_USE_CXX17")
    endif()
    target_compile_features(common_cli PUBLIC cxx_std_17)
    # Ensure PDB is generated even in Release mode
    if(MSVC)
        target_link_options(common_cli PUBLIC /DEBUG)
    endif()

    add_executable(sender_cli)
    add_subdirectory(cli/sender)
    target_link_libraries(sender_cli PUBLIC common_cli apsi)
    if (APPLE)
        target_compile_options(common_cli PUBLIC -DHAVE_LONG_LONG)
    endif()

    add_executable(receiver_cli)
    add_subdirectory(cli/receiver)
    target_link_libraries(receiver_cli PUBLIC common_cli apsi)

    add_executable(pd_tool)
    add_subdirectory(cli/pd_tool)
    target_include_directories(pd_tool PRIVATE cli)
    target_include_directories(pd_tool PRIVATE ${TCLAP_INCLUDE_DIRS})
    target_link_libraries(pd_tool apsi)
endif()
