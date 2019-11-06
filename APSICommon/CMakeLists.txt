# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(APSICommon VERSION 1.0.0 LANGUAGES CXX C)

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

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${PROJECT_SOURCE_DIR}/../bin)
set(PROJECT_TARGETS_FILENAME ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Targets.cmake)
set(PROJECT_CONFIG_IN_FILENAME ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in)
set(PROJECT_CONFIG_FILENAME ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake)
set(PROJECT_CONFIG_VERSION_FILENAME ${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}ConfigVersion.cmake)
set(PROJECT_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
set(PROJECT_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})

# Find module scripts
set(FOURQ_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindFourQ.cmake)
set(LOG4CPLUS_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindLog4cplus.cmake)
set(MSGSL_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindMSGSL.cmake)
set(ZEROMQ_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindZeroMQ.cmake)
set(ZEROMQPP_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindZeroMQpp.cmake)

# For locating all modules
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

# Should we build a shared library?
set(DEFAULT_LIB_BUILD_TYPE "Static")
if(NOT APSICommon_LIB_BUILD_TYPE)
    set(APSICommon_LIB_BUILD_TYPE ${DEFAULT_LIB_BUILD_TYPE} CACHE
        STRING "${PROJECT_NAME} build type" FORCE)
    set_property(CACHE APSICommon_LIB_BUILD_TYPE PROPERTY
        STRINGS "Static" "Shared")
endif()
message(STATUS "${PROJECT_NAME} build type: ${APSICommon_LIB_BUILD_TYPE}")

# Import Microsoft SEAL
find_package(SEAL 3.4.4 EXACT REQUIRED)

# Import Kuku
find_package(Kuku 1.1.1 EXACT REQUIRED)

# Import Microsoft GSL
if(MSGSL_ROOT)
    unset(MSGSL_INCLUDE_DIR CACHE)
endif()
find_package(MSGSL MODULE REQUIRED)

# Import ZeroMQ
if(ZeroMQ_ROOT)
    unset(ZEROMQ_INCLUDE_DIR CACHE)
    unset(ZEROMQ_LIBRARY_DIR CACHE)
    unset(ZEROMQ_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQ MODULE REQUIRED)

# Import ZeroMQpp
if(ZeroMQpp_ROOT)
    unset(ZEROMQPP_INCLUDE_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_PATH CACHE)
endif()
find_package(ZeroMQpp MODULE REQUIRED)

# Import FourQ
if(FourQ_ROOT)
    unset(FOURQ_INCLUDE_DIR CACHE)
    unset(FOURQ_LIBRARY_DIR CACHE)
    unset(FOURQ_LIBRARY_PATH CACHE)
endif()
find_package(FourQ MODULE REQUIRED)

# Import Log4cplus
if(Log4cplus_ROOT)
    unset(LOG4CPLUS_INCLUDE_DIR CACHE)
    unset(LOG4CPLUS_LIBRARY_DIR CACHE)
    unset(LOG4CPLUS_LIBRARY_PATH CACHE)
endif()
find_package(Log4cplus MODULE REQUIRED)

# Create library but add no source files yet
if(APSICommon_LIB_BUILD_TYPE STREQUAL "Shared")
    add_library(Common SHARED "")

    # Set SOVERSION for shared library
    set_target_properties(Common PROPERTIES
        SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
else()
    add_library(Common STATIC "")

    # For a static library indicate version in the filename
    set_target_properties(Common PROPERTIES
        OUTPUT_NAME apsi_common-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
endif()

# Set VERSION for all library build types
set_target_properties(Common PROPERTIES
    VERSION ${APSICommon_VERSION})

# Set PIC for all build types
set_target_properties(Common PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

# C++14
target_compile_features(Common PUBLIC cxx_std_14)

# Defines
message(WARNING "${PROJECT_NAME} adding define -DHAVE_CONFIG; needed?")
target_compile_options(Common PUBLIC -DHAVE_CONFIG)
message(WARNING "${PROJECT_NAME} adding define -DUSE_SECURE_SEED; needed?")
target_compile_options(Common PUBLIC -DUSE_SECURE_SEED)
message(WARNING "${PROJECT_NAME} adding define -D_AMD64_; needed?")
target_compile_options(Common PUBLIC -D_AMD64_)
message(WARNING "${PROJECT_NAME} adding define -D_AVX2_; needed?")
target_compile_options(Common PUBLIC -D_AVX2_)
if (NOT APPLE)
    message(WARNING "${PROJECT_NAME} adding define -D_ASM_; needed?")
    target_compile_options(Common PUBLIC -D_ASM_)
endif()
message(WARNING "${PROJECT_NAME} adding define -D__LINUX__; needed?")
target_compile_options(Common PUBLIC -D__LINUX__)
message(WARNING "${PROJECT_NAME} adding compile option -maes; needed?")
target_compile_options(Common PUBLIC -maes)
message(WARNING "${PROJECT_NAME} adding compile option -march=native; needed?")
target_compile_options(Common PUBLIC -march=native)

# Link required libraries
target_link_libraries(Common PUBLIC
    SEAL::seal
    MSGSL::MSGSL
    Kuku::kuku
    ZeroMQ::ZeroMQ
    ZeroMQpp::ZeroMQpp
    FourQ::FourQ
    Log4cplus::Log4cplus)
if (NOT APPLE)
    target_link_libraries(Common PUBLIC stdc++fs)
endif()

# Add source files to library
add_subdirectory(apsi)

# Add local include directories for build
target_include_directories(Common PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${PROJECT_INCLUDES_INSTALL_DIR}>)

# Associate APSI to export APSICommonTargets
install(TARGETS Common EXPORT APSICommonTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME}
    INSTALL_DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Export the targets
export(EXPORT APSICommonTargets
    FILE ${PROJECT_TARGETS_FILENAME}
    NAMESPACE APSI::)

# Create the CMake config file
configure_file(${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT APSICommonTargets
    NAMESPACE APSI::
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${PROJECT_CONFIG_VERSION_FILENAME}
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ExactVersion)

# Install config and module files
install(
    FILES
        ${PROJECT_CONFIG_FILENAME}
        ${PROJECT_CONFIG_VERSION_FILENAME}
        ${FOURQ_FIND_MODULE_PATH}
        ${LOG4CPLUS_FIND_MODULE_PATH}
        ${MSGSL_FIND_MODULE_PATH}
        ${ZEROMQ_FIND_MODULE_PATH}
        ${ZEROMQPP_FIND_MODULE_PATH}
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# We export APSICommonTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT APSICommonTargets
    NAMESPACE APSI::
    FILE ${PROJECT_TARGETS_FILENAME})
