# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(CommonCLI VERSION 1.0.0 LANGUAGES CXX C)

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
set(TCLAP_FIND_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/FindTCLAP.cmake)

# For locating all modules
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

# Should we build a shared library?
set(DEFAULT_LIB_BUILD_TYPE "Static")
if(NOT CommonCLI_LIB_BUILD_TYPE)
    set(CommonCLI_LIB_BUILD_TYPE ${DEFAULT_LIB_BUILD_TYPE} CACHE
        STRING "${PROJECT_NAME} build type" FORCE)
    set_property(CACHE CommonCLI_LIB_BUILD_TYPE PROPERTY
        STRINGS "Static" "Shared")
endif()
message(STATUS "${PROJECT_NAME} build type: ${CommonCLI_LIB_BUILD_TYPE}")

# Import APSICommon
find_package(APSICommon 1.0.0 EXACT REQUIRED
    PATHS ${PROJECT_SOURCE_DIR}/../APSICommon/cmake
)

# Import TCLAP
if(TCLAP_ROOT)
    unset(TCLAP_INCLUDE_DIR CACHE)
endif()
find_package(TCLAP MODULE REQUIRED)

# Create library but add no source files yet
if(CommonCLI_LIB_BUILD_TYPE STREQUAL "Shared")
    add_library(CommonCLI SHARED "")

    # Set SOVERSION for shared library
    set_target_properties(CommonCLI PROPERTIES
        SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
else()
    add_library(CommonCLI STATIC "") 

    # For a static library indicate version in the filename
    set_target_properties(CommonCLI PROPERTIES
        OUTPUT_NAME common_cli-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
endif()

# Set VERSION for all library build types
set_target_properties(CommonCLI PROPERTIES
    VERSION ${CommonCLI_VERSION})

# Set PIC for all build types
set_target_properties(CommonCLI PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

# C++14
target_compile_features(CommonCLI PUBLIC cxx_std_14)

# Link required libraries
target_link_libraries(CommonCLI PUBLIC
    APSI::Common
    TCLAP::TCLAP)

# Add source files to library
target_sources(CommonCLI PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/common_utils.cpp
)

# Add local include directories for build
target_include_directories(CommonCLI PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${PROJECT_INCLUDES_INSTALL_DIR}>)

# Associate APSI to export CommonCLITargets
install(TARGETS CommonCLI EXPORT CommonCLITargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME}
    INSTALL_DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Export the targets
export(EXPORT CommonCLITargets
    FILE ${PROJECT_TARGETS_FILENAME}
    NAMESPACE APSI::)

# Create the CMake config file
configure_file(${PROJECT_CONFIG_IN_FILENAME} ${PROJECT_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT CommonCLITargets
    NAMESPACE APSI::
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${PROJECT_CONFIG_VERSION_FILENAME}
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ExactVersion)

# Install header files
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/base_clp.h
        ${CMAKE_CURRENT_LIST_DIR}/common_utils.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR})

# Install config and module files
install(
    FILES
        ${PROJECT_CONFIG_FILENAME}
        ${PROJECT_CONFIG_VERSION_FILENAME}
        ${PROJECT_CONFIG_VERSION_FILENAME}
        ${TCLAP_FIND_MODULE_PATH}
    DESTINATION ${PROJECT_CONFIG_INSTALL_DIR})

# We export CommonCLITargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT CommonCLITargets
    NAMESPACE APSI::
    FILE ${PROJECT_TARGETS_FILENAME})
