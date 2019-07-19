cmake_minimum_required(VERSION 3.10)

project(Cuckoo VERSION 1.0 LANGUAGES CXX C)

if(${MSVC})
    message(FATAL_ERROR "Please build using the attached Visual Studio solution/project files.")
endif()

add_compile_options(
    "-march=native" 
    "-Wno-ignored-attributes")

# Build in Release mode by default; otherwise use selected option
set(CUCKOO_DEFAULT_BUILD_TYPE "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${CUCKOO_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# In Debug mode enable also CUCKOO_DEBUG by default
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CUCKOO_DEBUG_DEFAULT ON)
else()
    set(CUCKOO_DEBUG_DEFAULT OFF)
endif()

# Required files and directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${Cuckoo_SOURCE_DIR}/../lib)
set(CUCKOO_INCLUDES_INSTALL_DIR include)
set(CUCKOO_CONFIG_IN_FILENAME ${Cuckoo_SOURCE_DIR}/cmake/CuckooConfig.cmake.in)
set(CUCKOO_CONFIG_FILENAME ${Cuckoo_SOURCE_DIR}/cmake/CuckooConfig.cmake)
set(CUCKOO_TARGETS_FILENAME ${Cuckoo_SOURCE_DIR}/cmake/CuckooTargets.cmake)
set(CUCKOO_CONFIG_VERSION_FILENAME ${Cuckoo_SOURCE_DIR}/cmake/CuckooConfigVersion.cmake)
set(CUCKOO_CONFIG_INSTALL_DIR lib/cmake/Cuckoo)

# For extra modules we might have 
list(APPEND CMAKE_MODULE_PATH ${Cuckoo_SOURCE_DIR}/cmake)

# Are we using CUCKOO_DEBUG?
set(CUCKOO_DEBUG ${CUCKOO_DEBUG_DEFAULT})
message(STATUS "Cuckoo debug mode: ${CUCKOO_DEBUG}")

include(CheckIncludeFile)

# Do we have necessary intrinsics available?
check_include_file("wmmintrin.h" HAVE_WMMINTRIN_HEADER)
if(NOT HAVE_WMMINTRIN_HEADER)
    message(FATAL_ERROR "Could not find wmmintrin.h --- cannot build without AES-NI available.")
endif()

# Create library but add no source files yet
add_library(cuckoo STATIC "")
set_property(TARGET cuckoo PROPERTY POSITION_INDEPENDENT_CODE ON)

# Add source files to library and header files to install
add_subdirectory(cuckoo)

# Add local include directories for build
target_include_directories(cuckoo PUBLIC 
    $<BUILD_INTERFACE:${Cuckoo_SOURCE_DIR}>)

# Require C++17
target_compile_features(cuckoo PUBLIC cxx_std_17)

# Associate Cuckoo to export cuckoo_export
install(TARGETS cuckoo EXPORT cuckoo_export
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION ${CUCKOO_INCLUDES_INSTALL_DIR})

# Export the targets
export(EXPORT cuckoo_export
    FILE ${CUCKOO_TARGETS_FILENAME}
    NAMESPACE Cuckoo::)

# Create the CMake config file
configure_file(${CUCKOO_CONFIG_IN_FILENAME} ${CUCKOO_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT cuckoo_export
    FILE CuckooTargets.cmake
    NAMESPACE Cuckoo::
    DESTINATION ${CUCKOO_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${CUCKOO_CONFIG_VERSION_FILENAME}
    VERSION ${Cuckoo_VERSION}
    COMPATIBILITY ExactVersion)

# Install other files 
install(
    FILES
        ${CUCKOO_CONFIG_FILENAME}
        ${CUCKOO_CONFIG_VERSION_FILENAME}
    DESTINATION ${CUCKOO_CONFIG_INSTALL_DIR})
