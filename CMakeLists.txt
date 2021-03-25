# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

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

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
    cmake_policy(SET CMP0077 NEW)
endif()

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)

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

# TODO: C++17 or C++14, extra configurations or check for_each_n for C++17
# Description:
#     SEAL_USE_CXX17 and SEAL_USE_STD_FOR_EACH_N depends on compiler version when vcpkg installs SEAL.
#     If SEAL_USE_CXX17 is ON, then GNU CC 7+. --> c++17
#     If APSI_BUILD_CLI is ON, then GNU CC 8+. --> std::filesystem
#     If SEAL_USE_STD_FOR_EACH_N is ON, then GNU CC 9+. --> std::for_each_n
# [option] APSI_USE_CXX17_OPTION_STR (default: ON)
# Use C++17, use C++14 otherwise.
set(APSI_USE_CXX17_OPTION_STR "Use C++17")
option(APSI_USE_CXX17 ${APSI_USE_CXX17_OPTION_STR} ON)
# Enable features from C++17 if available, disable features if set to OFF.
#include(EnableCXX17)
message(STATUS "APSI_USE_CXX17: ${APSI_USE_CXX17}")

# Enable security-related compile options (MSVC only)
set(APSI_SECURE_COMPILE_OPTIONS_OPTION_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(APSI_SECURE_COMPILE_OPTIONS ${APSI_SECURE_COMPILE_OPTIONS_OPTION_STR} OFF)
mark_as_advanced(APSI_SECURE_COMPILE_OPTIONS)

# Path for output
set(OUTLIB_PATH "lib")

# Required files and directories
include(GNUInstallDirs)

# Source tree
set(APSI_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/APSIConfig.cmake.in)
set(APSI_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}) # TODO: remove this
set(APSI_CONFIG_H_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/common/native/apsi/config.h.in) # TODO: change this

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(APSI_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSITargets.cmake)
set(APSI_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSIConfig.cmake)
set(APSI_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSIConfigVersion.cmake)
set(APSI_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/common/native/apsi/config.h) # TODO: change this

# Install
set(APSI_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
set(APSI_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})

# pkg-config
# TODO: not provided yet

#########################
# External Dependencies #
#########################
# TODO: Do we care if vcpkg is not used?
# TODO: DO we want to hide vcpkg variables and dep dirs from ccmake?
# TODO: "xxx: not found" won't print, because CMake Error at vcpkg.cmake occurs first!

# Microsoft SEAL
find_package(SEAL 3.6 QUIET REQUIRED)
if(NOT SEAL_FOUND)
    message(FATAL_ERROR "Microsoft SEAL: not found")
else()
    message(STATUS "Microsoft SEAL: found")
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
    message(STATUS "    flatc path: ${FLATBUFFERS_FLATC_PATH}")
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

# [Option] APSI_BUILD_TESTS (default: ON)
set(APSI_BUILD_TESTS_OPTION_STR "Build unit and integration tests for APSI")
option(APSI_BUILD_TESTS ${APSI_BUILD_TESTS_OPTION_STR} ON)
if(APSI_BUILD_TESTS)
    # Google Test
    find_package(GTest CONFIG REQUIRED)
    if(NOT GTest_FOUND)
        message(FATAL_ERROR "GTest: not found")
    else()
        message(STATUS "GTest: found")
    endif()
endif()

# [Option] APSI_BUILD_CLI (default: ON)
set(APSI_BUILD_CLI_OPTION_STR "Build example command line interface applications")
cmake_dependent_option(APSI_BUILD_CLI ${APSI_BUILD_CLI_OPTION_STR} ON "APSI_USE_ZMQ;APSI_USE_LOG4CPLUS" OFF)
if (APSI_BUILD_CLI)
    # TCLAP
    find_path(TCLAP_INCLUDE_DIRS "tclap/Arg.h")
    if(TCLAP_INCLUDE_DIRS STREQUAL "TCLAP_INCLUDE_DIRS-NOTFOUND")
        message(FATAL_ERROR "TCLAP: not found")
    else()
        message(STATUS "TCLAP: found")
        message(STATUS "    TCLAP_INCLUDE_DIRS: ${TCLAP_INCLUDE_DIRS}")
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

# TODO: what is the new filesystem structure?

# Add source files to library and header files to install
# TODO: combine into a single variable
set(APSI_COMMON_SOURCE_FILES "")
add_subdirectory(common/native/apsi)
set(APSI_RECEIVER_SOURCE_FILES "")
add_subdirectory(receiver/native/apsi)
set(APSI_SENDER_SOURCE_FILES "")
add_subdirectory(sender/native/apsi)

# Create the config file
configure_file(${APSI_CONFIG_H_IN_FILENAME} ${APSI_CONFIG_H_FILENAME})
install(
    FILES ${APSI_CONFIG_H_FILENAME}
    DESTINATION ${APSI_INCLUDES_INSTALL_DIR}/apsi)

add_library(common STATIC ${APSI_COMMON_SOURCE_FILES})
set_target_properties(common PROPERTIES OUTPUT_NAME apsi_common-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_set_language(common)
target_include_directories(common PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
target_include_directories(common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_set_version(common)
apsi_link_threads(common)
apsi_install_target(common APSITargets)

target_link_libraries(common
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
if (APSI_USE_LOG4CPLUS)
    target_link_libraries(common PUBLIC log4cplus::log4cplus)
endif()
if(APSI_USE_ZMQ)
    target_link_libraries(common PUBLIC libzmq-static cppzmq-static)
endif()

# Set AVX or AVX2 flags
include(FindAVX)
check_for_avx(common)
if (HAVE_AVX2_EXTENSIONS)
    target_compile_options(common PUBLIC -D_AVX2_)
elseif(HAVE_AVX_EXTENSIONS)
    target_compile_options(common PUBLIC -D_AVX_)
else()
    target_compile_options(common PUBLIC -D_GENERIC_)
endif()

if (MSVC)
    target_compile_options(common PUBLIC -D__WINDOWS__)
else()
    target_compile_options(common PUBLIC -D__LINUX__)
    target_compile_options(common PUBLIC -march=native)
endif()

# Defines for FourQlib
target_compile_options(common PUBLIC -DHAVE_CONFIG)
target_compile_options(common PUBLIC -DUSE_SECURE_SEED)
target_compile_options(common PUBLIC -D_AMD64_)
target_compile_options(common PUBLIC -DUSE_ENDO=true)

#############################
# APSI receiver C++ library #
#############################

add_library(receiver STATIC ${APSI_RECEIVER_SOURCE_FILES})
set_target_properties(receiver PROPERTIES OUTPUT_NAME apsi_receiver-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_set_language(receiver)
target_include_directories(receiver PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/receiver/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_set_version(receiver)
apsi_link_threads(receiver)
apsi_install_target(receiver APSITargets)
target_link_libraries(receiver PUBLIC common)

###########################
# APSI sender C++ library #
###########################

add_library(sender STATIC ${APSI_SENDER_SOURCE_FILES})
set_target_properties(sender PROPERTIES OUTPUT_NAME apsi_sender-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_set_language(sender)
target_include_directories(sender PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/sender/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_set_version(sender)
apsi_link_threads(sender)
apsi_install_target(sender APSITargets)
target_link_libraries(sender PUBLIC common)

# Set secure compile options if APSI_SECURE_COMPILE_OPTIONS is ON; only supported on MSVC
if(APSI_SECURE_COMPILE_OPTIONS)
    apsi_set_secure_compile_options(seal PUBLIC)
endif()

#################################
# Installation and CMake config #
#################################

# TODO: after directory structure is set.

###################
# APSI unit tests #
###################

if(APSI_BUILD_TESTS)
    add_executable(unit_tests)
    add_subdirectory(tests/unit/src)
    target_link_libraries(unit_tests common sender receiver GTest::gtest)
endif()

##########################
# APSI integration tests #
##########################

if(APSI_BUILD_TESTS)
    add_executable(integration_tests)
    add_subdirectory(tests/integration/src)
    target_link_libraries(integration_tests common sender receiver GTest::gtest)
endif()

##########################
# Command Line Interface #
##########################

if(APSI_BUILD_CLI)
    add_library(common_cli OBJECT)
    add_subdirectory(cli/common)
    target_include_directories(common_cli PUBLIC cli)
    target_include_directories(common_cli PUBLIC ${TCLAP_INCLUDE_DIRS})
    target_link_libraries(common_cli PUBLIC common)

    add_executable(sender_cli)
    add_subdirectory(cli/sender)
    target_link_libraries(sender_cli PUBLIC common_cli sender)
    if(!MSVC)
        target_link_libraries(sender_cli PUBLIC stdc++fs)
    endif()
    if (APPLE)
        target_compile_options(common_cli PUBLIC -DHAVE_LONG_LONG)
    endif()

    add_executable(receiver_cli)
    add_subdirectory(cli/receiver)
    target_link_libraries(receiver_cli PUBLIC common_cli receiver)
    if (!MSVC)
        target_link_libraries(receiver_cli PUBLIC stdc++fs)
    endif()

    add_executable(pd_tool)
    add_subdirectory(cli/pd_tool)
    target_include_directories(pd_tool PRIVATE cli)
    target_include_directories(pd_tool PRIVATE ${TCLAP_INCLUDE_DIRS})
    target_link_libraries(pd_tool common)
endif()
