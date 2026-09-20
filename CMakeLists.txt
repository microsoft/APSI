# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

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

project(APSI VERSION 1.0.0 LANGUAGES CXX C)

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

# Whether this is a Debug build. It reflects CMAKE_BUILD_TYPE and so means something only for
# single-configuration generators; all it gates is the extra warning flags below. The APSI_DEBUG
# macro the sources actually use is set per configuration on the target further down.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(APSI_DEBUG ON)
    # In Debug mode, enable extra compiler flags.
    include(EnableCXXCompilerFlags)
else()
    set(APSI_DEBUG OFF)
endif()
message(STATUS "APSI debug mode: ${APSI_DEBUG}")

# Enable security-related compile options (MSVC only)
set(APSI_SECURE_COMPILE_OPTIONS_OPTION_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(APSI_SECURE_COMPILE_OPTIONS ${APSI_SECURE_COMPILE_OPTIONS_OPTION_STR} OFF)
mark_as_advanced(APSI_SECURE_COMPILE_OPTIONS)

# Enable AVX implementation
set(APSI_USE_AVX_OPTION_STR "Use AVX extensions if available")
option(APSI_USE_AVX ${APSI_USE_AVX_OPTION_STR} ON)
mark_as_advanced(APSI_USE_AVX)

# Enable AVX2 implementation
set(APSI_USE_AVX2_OPTION_STR "Use AVX2 extensions if available")
option(APSI_USE_AVX2 ${APSI_USE_AVX2_OPTION_STR} ON)
mark_as_advanced(APSI_USE_AVX2)

# Enable ASM implementation
set(APSI_USE_ASM_OPTION_STR "Use ASM implementation (static UNIX builds only)")
option(APSI_USE_ASM ${APSI_USE_ASM_OPTION_STR} ON)
mark_as_advanced(APSI_USE_ASM)

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
# The version range is checked here rather than passed to find_package, because SEAL installs a
# SameMinorVersion config file that would reject any minor version other than its own.
set(APSI_SEAL_MINIMUM_VERSION 4.4.5)
set(APSI_SEAL_MAXIMUM_VERSION_EXCLUSIVE 5.0.0)
find_package(SEAL CONFIG QUIET REQUIRED)
if(NOT SEAL_FOUND)
    message(FATAL_ERROR "Microsoft SEAL: not found")
elseif(SEAL_VERSION VERSION_LESS APSI_SEAL_MINIMUM_VERSION
        OR SEAL_VERSION VERSION_GREATER_EQUAL APSI_SEAL_MAXIMUM_VERSION_EXCLUSIVE)
    message(FATAL_ERROR
        "Microsoft SEAL: found ${SEAL_VERSION}, but APSI requires at least "
        "${APSI_SEAL_MINIMUM_VERSION} and older than ${APSI_SEAL_MAXIMUM_VERSION_EXCLUSIVE}")
else()
    message(STATUS "Microsoft SEAL: found (${SEAL_VERSION})")
endif()

# Microsoft GSL
# APSI's public headers include <gsl/span>, so this is part of the installed interface and not
# merely a build-time convenience. SEAL is built here with SEAL_USE_MSGSL=OFF and so does not
# propagate GSL, and relying on vcpkg's global include directory would leave any consumer
# outside a vcpkg manifest unable to include an APSI header at all.
find_package(Microsoft.GSL CONFIG QUIET REQUIRED)
if(NOT Microsoft.GSL_FOUND)
    message(FATAL_ERROR "Microsoft GSL: not found")
else()
    message(STATUS "Microsoft GSL: found")
endif()

# Microsoft Kuku
find_package(Kuku CONFIG QUIET REQUIRED)
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
elseif (NOT TARGET JsonCpp::JsonCpp)
    # jsoncpp exports the namespaced target from 1.9.5 on; an older one satisfies find_package
    # and then leaves the link unresolved.
    message(FATAL_ERROR "jsoncpp: found, but it does not define JsonCpp::JsonCpp; "
                        "jsoncpp 1.9.5 or newer is required")
else()
    message(STATUS "jsoncpp: found")
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
cmake_dependent_option(APSI_BUILD_CLI ${APSI_BUILD_CLI_OPTION_STR} OFF "APSI_USE_ZMQ" OFF)
# cmake_dependent_option silently forces the value to OFF when the condition fails, which for a
# request the user made explicitly is the wrong answer: the build simply produces no CLI and says
# nothing about why. Detect that case and say so.
if(DEFINED CACHE{APSI_BUILD_CLI} AND NOT APSI_USE_ZMQ)
    get_property(apsi_cli_requested CACHE APSI_BUILD_CLI PROPERTY VALUE)
    if(apsi_cli_requested)
        message(FATAL_ERROR "APSI_BUILD_CLI requires APSI_USE_ZMQ=ON; the CLI has no other transport")
    endif()
endif()
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

# APSI_DEBUG marks a debug build for APSI's own sources, which use it to enable extra
# validation. It is set per configuration rather than written into config.h, because a
# multi-configuration generator such as Visual Studio or Xcode configures once and builds every
# configuration from that single generated header: a configure-time #cmakedefine there is fixed
# to whatever CMAKE_BUILD_TYPE happened to say, and so was never set in a Visual Studio Debug
# build. PRIVATE and BUILD_INTERFACE because only these sources consult it; a consumer compiling
# against an installed APSI must not have its own build flip a macro inside APSI's headers.
target_compile_definitions(apsi PRIVATE $<BUILD_INTERFACE:$<$<CONFIG:Debug>:APSI_DEBUG>>)

# JsonCpp::JsonCpp forwards to whichever of jsoncpp_static or jsoncpp_lib the installed jsoncpp
# provides; naming one of those directly fixes APSI to a single jsoncpp linkage.
target_link_libraries(apsi
    PUBLIC SEAL::seal
    PUBLIC Microsoft.GSL::GSL
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC JsonCpp::JsonCpp)
if(APSI_USE_ZMQ)
    target_link_libraries(apsi PUBLIC libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
#
# PRIVATE throughout. These configure the vendored FourQ sources, which are compiled into this
# target and reached only from .cpp files, so no installed header needs them. Exporting them
# would impose FourQ's build configuration on every consumer -- including naming the host's
# operating system and architecture, which are not necessarily the consumer's, and claiming the
# very generic HAVE_CONFIG, which a consumer may define for its own purposes.
target_compile_options(apsi PRIVATE -DHAVE_CONFIG)
target_compile_options(apsi PRIVATE -DUSE_SECURE_SEED)
target_compile_options(apsi PRIVATE -DUSE_ENDO=true)

# Set system. The vendored FourQ sources require one of these to select an OS_TARGET.
if(WIN32)
    target_compile_options(apsi PRIVATE -D__WINDOWS__)
elseif (UNIX)
    target_compile_options(apsi PRIVATE -D__LINUX__)
else()
    message(FATAL_ERROR "Unsupported platform: APSI's vendored FourQ sources build only on "
                        "Windows or a UNIX-like system.")
endif()

# Detect architecture
include(DetectArch)
if(APSI_FOURQ_ARM64)
    # _ARM64_ needs to be set if the ARM64 optimizations are used
    # (in UNIX) or the generic implementation is used (Windows)
    target_compile_options(apsi PRIVATE -D_ARM64_)
endif()
if(CMAKE_SYSTEM_PROCESSOR STREQUAL x86)
    target_compile_options(apsi PRIVATE -D_X86_)
endif()

if(APSI_FOURQ_AMD64)
    target_compile_options(apsi PRIVATE -D_AMD64_)
    message(STATUS "FourQlib optimization: arch=AMD64")
elseif(APSI_FOURQ_ARM64 AND UNIX)
    message(STATUS "FourQlib optimization: arch=ARM64")
else()
    target_compile_options(apsi PRIVATE -D_GENERIC_)
    message(STATUS "FourQlib optimization: arch=GENERIC")
endif()

# Detect AVX instructions
if(APSI_FOURQ_AMD64 AND (APSI_USE_AVX OR APSI_USE_AVX2))
    include(FindAVX)
    check_for_avx(apsi)
    if(HAVE_AVX2_EXTENSIONS AND APSI_USE_AVX2)
        target_compile_options(apsi PRIVATE -D_AVX2_)
        set(APSI_USE_AVX OFF CACHE BOOL ${APSI_USE_AVX_OPTION_STR} FORCE)
        message(STATUS "FourQlib optimization: simd=AVX2")
    elseif(HAVE_AVX_EXTENSIONS AND APSI_USE_AVX)
        target_compile_options(apsi PRIVATE -D_AVX_)
        set(APSI_USE_AVX2 OFF CACHE BOOL ${APSI_USE_AVX2_OPTION_STR} FORCE)
        message(STATUS "FourQlib optimization: simd=AVX")
    else()
        set(APSI_USE_AVX OFF CACHE BOOL ${APSI_USE_AVX_OPTION_STR} FORCE)
        set(APSI_USE_AVX2 OFF CACHE BOOL ${APSI_USE_AVX2_OPTION_STR} FORCE)
        message(STATUS "FourQlib optimization: simd=OFF")
    endif()
else()
    set(APSI_USE_AVX OFF CACHE BOOL ${APSI_USE_AVX_OPTION_STR} FORCE)
    set(APSI_USE_AVX2 OFF CACHE BOOL ${APSI_USE_AVX2_OPTION_STR} FORCE)
    message(STATUS "FourQlib optimization: simd=OFF")
endif()

# Use optimized assembly on UNIX
#
# Restricted to AMD64 because that is the only architecture the vendored FourQ ships assembly
# for. Without that condition an aarch64 Linux build defines _ASM_, so eccp2_core.c calls
# fp2mul1271_a and friends, while third_party/fourq/ARM64 contributes no sources to define
# them: the build fails at link time. A failure to detect an assembler is handled the same way,
# rather than leaving APSI_USE_ASM on with nothing to assemble.
if(APSI_USE_ASM AND APSI_FOURQ_AMD64 AND UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
    check_language(ASM)
endif()
if(APSI_USE_ASM AND APSI_FOURQ_AMD64 AND UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW
        AND CMAKE_ASM_COMPILER)
    enable_language(ASM)
    target_compile_options(apsi PRIVATE -D_ASM_)
    message(STATUS "FourQlib optimization: asm=ON")
else()
    set(APSI_USE_ASM OFF CACHE BOOL ${APSI_USE_ASM_OPTION_STR} FORCE)
    message(STATUS "FourQlib optimization: asm=OFF")
endif()

# Add source files to library and header files to install
# Must follow configurations for FourQlib
set(APSI_SOURCE_FILES "")
add_subdirectory(third_party/fourq)
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
    target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_LIST_DIR}/tests)
    target_link_libraries(unit_tests apsi GTest::gtest)
endif()

##########################
# APSI integration tests #
##########################

if(APSI_BUILD_TESTS)
    add_executable(integration_tests)
    add_subdirectory(tests/integration/src)
    target_include_directories(integration_tests PRIVATE ${CMAKE_CURRENT_LIST_DIR}/tests)
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
