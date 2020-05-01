# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

###################################################
# Project APSI includes the following components: #
#   1. APSI common C++ library                    #
#   2. APSI sender C++ library                    #
#   3. APSI receiver C++ library                  #
#   4. APSI unit tests                            #
#   5. APSI integration tests                     #
#   6. TODO: APSI receiver C export library       #
###################################################

project(APSI VERSION 1.0.0 LANGUAGES CXX C)

# Check operating system: for Windows, use Visual Studio solution/project files.
if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

########################
# Global configuration #
########################

# [Option] CMAKE_BUILD_TYPE
# Build in Release mode by default; otherwise use selected option
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# [Flag] APSI_DEBUG
# In Debug mode, enable APSI_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(APSI_DEBUG ON)
else()
    set(APSI_DEBUG OFF)
endif()
message(STATUS "APSI debug mode: ${APSI_DEBUG}")

# [Option] APSI_BUILD_TESTS
set(APSI_BUILD_TESTS_OPTION_STR "Build C++ tests for Microsoft SEAL")
option(APSI_BUILD_TESTS ${APSI_BUILD_TESTS_OPTION_STR} OFF)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# TODO: global choice of C++14 or 17

# [Option] CXX compiler flags
# For easier adding of CXX compiler flags
include(CheckCXXCompilerFlag)
function(enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

# In Debug mode, enable extra compiler flags.
if(APSI_DEBUG)
  enable_cxx_compiler_flag_if_supported("-Wall")
  enable_cxx_compiler_flag_if_supported("-Wextra")
  enable_cxx_compiler_flag_if_supported("-Wconversion")
  enable_cxx_compiler_flag_if_supported("-Wshadow")
  enable_cxx_compiler_flag_if_supported("-pedantic")
endif()

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${APSI_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${APSI_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${APSI_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${APSI_SOURCE_DIR}/bin)
# TODO: might need serious modification
set(APSI_TARGETS_FILENAME ${APSI_SOURCE_DIR}/cmake/APSITargets.cmake)
set(APSI_CONFIG_IN_FILENAME ${APSI_SOURCE_DIR}/cmake/APSIConfig.cmake.in)
set(APSI_CONFIG_FILENAME ${APSI_SOURCE_DIR}/cmake/APSIConfig.cmake)
set(APSI_CONFIG_VERSION_FILENAME ${APSI_SOURCE_DIR}/cmake/APSIConfigVersion.cmake)
set(APSI_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
set(APSI_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/APSI-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})

# For locating all modules
list(APPEND CMAKE_MODULE_PATH ${APSI_SOURCE_DIR}/cmake)

# include(CMakePushCheckState)
# include(CMakeDependentOption)
# include(CheckIncludeFiles)
# include(CheckCXXSourceRuns)
# include(CheckTypeSize)

# Should we build also the shared library?
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
if(MSVC AND BUILD_SHARED_LIBS)
    message(WARNING "This build system only supports a static build; disabling `BUILD_SHARED_LIBS`")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL ${BUILD_SHARED_LIBS_STR} FORCE)
endif()

##################################
# Macros for configuring targets #
##################################

# Set the C++ language version
macro(set_language target)
    target_compile_features(${target} PUBLIC cxx_std_14)
endmacro()

# Set the VERSION property
macro(set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${APSI_VERSION})
endmacro()

# Set the library filename to reflect version
macro(set_version_filename target)
    set_target_properties(${target} PROPERTIES OUTPUT_NAME ${target}-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(set_soversion target)
    set_target_properties(${target} PROPERTIES SOVERSION ${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${APSI_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link a thread library
macro(link_threads target)
    # Require thread library
    if(NOT TARGET Threads::Threads)
        set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
        set(THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package(Threads REQUIRED)
    endif()

    # Link Threads
    target_link_libraries(${target} PUBLIC Threads::Threads)
endmacro()

# Include target to given export
macro(install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

#########################
# External Dependencies #
#########################
# TODO: external dependencies are currently installed manually.
set(FOURQ_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindFourQ.cmake)
set(MSGSL_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindMSGSL.cmake)
set(ZEROMQ_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindZeroMQ.cmake)
set(ZEROMQPP_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindZeroMQpp.cmake)
find_package(SEAL 3.5 REQUIRED)
find_package(Kuku 1.1.1 EXACT REQUIRED)
if(MSGSL_ROOT)
    unset(MSGSL_INCLUDE_DIR CACHE)
endif()
find_package(MSGSL MODULE REQUIRED)
if(ZeroMQ_ROOT)
    unset(ZEROMQ_INCLUDE_DIR CACHE)
    unset(ZEROMQ_LIBRARY_DIR CACHE)
    unset(ZEROMQ_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQ MODULE REQUIRED)
if(ZeroMQpp_ROOT)
    unset(ZEROMQPP_INCLUDE_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQpp MODULE REQUIRED)
if(FourQ_ROOT)
    unset(FOURQ_INCLUDE_DIR CACHE)
    unset(FOURQ_LIBRARY_DIR CACHE)
    unset(FOURQ_LIBRARY_PATH CACHE)
endif()
find_package(FourQ MODULE REQUIRED)
find_package(log4cplus 3.0 REQUIRED)

# Microsoft SEAL + MSGSL + ZLIB
# MSGSL and ZLIB should be installed with Microsoft SEAL
if(NOT SEAL_USE_MSGSL)
#    message(FATAL_ERROR "Microsoft SEAL should be built with MSGSL enabled.")
endif()
if(NOT SEAL_USE_ZLIB)
#    message(FATAL_ERROR "Microsft SEAL should be built with ZLIB enabled.")
endif()

# Kuku

# ZeroMQ

# ZeroMQpp

# FourQ

# Log4cplus

# Use Google Test
if(APSI_BUILD_TESTS)
    # This follows the example in
    # https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.

    # Download
    message(STATUS "Setting up Google Test ...")
    add_subdirectory(thirdparty/googletest)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY thirdparty/googletest)
    if(result)
        message(WARNING "Failed to download Google Test (${result}); disabling `APSI_BUILD_TESTS`")
    endif()

    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    mark_as_advanced(BUILD_GMOCK)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(INSTALL_GTEST)

    # Build
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY thirdparty/googletest)
    if(result)
        message(WARNING "Failed to build Google Test (${result}); disabling `APSI_BUILD_TESTS`")
    endif()

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Set up the targets
    add_subdirectory(
        thirdparty/googletest/src
        thirdparty/googletest/build
        EXCLUDE_FROM_ALL)
endif()

###########################
# APSI common C++ library #
###########################

# Create an object library to compile sources only once
add_library(common STATIC)

# Add source files to library and header files to install
add_subdirectory(common/native/apsi)

# Set C++ language version and include directories for the object library
set_language(common)
target_include_directories(common PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)

# Link dependencies
#target_link_libraries(common PUBLIC
#    SEAL::seal
#    MSGSL::MSGSL
#    Kuku::kuku
#    ZeroMQ::ZeroMQ
#    ZeroMQpp::ZeroMQpp
#    FourQ::FourQ
#    log4cplus::log4cplus)
if (NOT APPLE)
    target_link_libraries(common PUBLIC stdc++fs)
endif()

# Defines
target_compile_options(common PUBLIC -DHAVE_CONFIG)
target_compile_options(common PUBLIC -DUSE_SECURE_SEED)
target_compile_options(common PUBLIC -D_AMD64_)
target_compile_options(common PUBLIC -D_AVX2_)
if (NOT APPLE)
    target_compile_options(common PUBLIC -D_ASM_)
endif()
target_compile_options(common PUBLIC -D__LINUX__)
target_compile_options(common PUBLIC -maes)
target_compile_options(common PUBLIC -march=native)

set_version(common)
set_target_properties(common PROPERTIES OUTPUT_NAME apsi_common-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
link_threads(common)
install_target(common APSITargets)

###########################
# APSI sender C++ library #
###########################

add_library(sender SHARED)
add_subdirectory(sender/native/apsi)
set_target_properties(sender PROPERTIES OUTPUT_NAME apsi_sender)
set_version(sender)
set_soversion(sender)
set_language(sender)
target_link_libraries(sender PUBLIC common)
target_include_directories(sender PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/sender/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
link_threads(sender)
install_target(sender APSITargets)

#############################
# APSI receiver C++ library #
#############################

add_library(receiver SHARED)
add_subdirectory(receiver/native/apsi)
set_target_properties(receiver PROPERTIES OUTPUT_NAME apsi_receiver)
set_version(receiver)
set_soversion(receiver)
set_language(receiver)
target_link_libraries(receiver PUBLIC common)
target_include_directories(receiver PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/receiver/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
link_threads(receiver)
install_target(receiver APSITargets)

###################
# APSI unit tests #
###################

# TODO: do we care about shared library tests?
if(APSI_BUILD_TESTS)
    add_executable(unit_tests)
    add_subdirectory(tests/unit/src)
    target_link_libraries(unit_tests common sender receiver gtest)
    if (NOT APPLE)
        target_link_libraries(unit_tests stdc++fs)
    endif()
endif()

##########################
# APSI integration tests #
##########################

# TODO: do we care about shared library tests?
if(APSI_BUILD_TESTS)
    add_executable(integration_tests)
    add_subdirectory(tests/integration/src)
    target_link_libraries(integration_tests common sender receiver gtest)
    if (NOT APPLE)
        target_link_libraries(integration_tests stdc++fs)
    endif()
endif()