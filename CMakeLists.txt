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
  #enable_cxx_compiler_flag_if_supported("-Wall")
  #enable_cxx_compiler_flag_if_supported("-Wextra")
  #enable_cxx_compiler_flag_if_supported("-Wconversion")
  #enable_cxx_compiler_flag_if_supported("-Wshadow")
  #enable_cxx_compiler_flag_if_supported("-pedantic")
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
macro(apsi_set_language target)
    target_compile_features(${target} PUBLIC cxx_std_14)
endmacro()

# Set the VERSION property
macro(apsi_set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${APSI_VERSION})
endmacro()

# Set the library filename to reflect version
macro(apsi_set_version_filename target)
    set_target_properties(${target} PROPERTIES OUTPUT_NAME ${target}-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(apsi_set_soversion target)
    set_target_properties(${target} PROPERTIES SOVERSION ${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(apsi_set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${APSI_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link a thread library
macro(apsi_link_threads target)
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
macro(apsi_install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

# Manually combine archives, using ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} to keep temporary files.
macro(apsi_combine_archives target dependency)
    if(CMAKE_HOST_WIN32)
        get_filename_component(CXX_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set(AR_CMD_PATH "${CXX_DIR}/llvm-ar.exe")
        file(TO_NATIVE_PATH "${AR_CMD_PATH}" AR_CMD_PATH)
        set(DEL_CMD "del")
        set(DEL_CMD_OPTS "")
    else()
        set(AR_CMD_PATH "ar")
        set(DEL_CMD "rm")
        set(DEL_CMD_OPTS "-rf")
    endif()
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${AR_CMD_PATH}" x $<TARGET_FILE:${target}>
        COMMAND "${AR_CMD_PATH}" x $<TARGET_FILE:${dependency}>
        COMMAND "${AR_CMD_PATH}" rcs $<TARGET_FILE:${target}> *.o
        COMMAND ${DEL_CMD} ${DEL_CMD_OPTS} *.o
        WORKING_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endmacro()

#########################
# External Dependencies #
#########################

function(create_cache_entries dir_name)
    set(cce_file_name ${dir_name}/cache_init.txt)
    file(WRITE  "${cce_file_name}" "set(CMAKE_C_COMPILER \"${CMAKE_C_COMPILER}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_CXX_COMPILER \"${CMAKE_CXX_COMPILER}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_TOOLCHAIN_FILE \"${CMAKE_TOOLCHAIN_FILE}\" CACHE FILEPATH \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_ABI ${ANDROID_ABI} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_NDK \"${ANDROID_NDK}\" CACHE FILEPATH \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_PLATFORM ${ANDROID_PLATFORM} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_ANDROID_ARCH_ABI ${CMAKE_ANDROID_ARCH_ABI} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_ANDROID_NDK \"${CMAKE_ANDROID_NDK}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_MAKE_PROGRAM \"${CMAKE_MAKE_PROGRAM}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_SYSTEM_NAME ${CMAKE_SYSTEM_NAME} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_SYSTEM_VERSION ${CMAKE_SYSTEM_VERSION} CACHE STRING \"\" FORCE)\n")
endfunction()

set(THIRDPARTY_DIR ${APSI_SOURCE_DIR}/thirdparty)

# Microsoft SEAL + MSGSL + ZLIB
# MSGSL and ZLIB should be installed with Microsoft SEAL
# Download and configure
if(NOT MSVC)
    message(STATUS "Setting up Microsoft SEAL ...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/seal)
    if(result)
        message(FATAL_ERROR "Failed to download Microsoft SEAL (${result})")
    endif()
    mark_as_advanced(SEAL_BUILD_EXAMPLES)
    mark_as_advanced(SEAL_BUILD_SEAL_C)
    mark_as_advanced(SEAL_BUILD_TESTS)
    mark_as_advanced(SEAL_USE_CXX17)
    mark_as_advanced(SEAL_USE_INTRIN)
    mark_as_advanced(SEAL_USE_MSGSL)
    mark_as_advanced(SEAL_USE_ZLIB)
    mark_as_advanced(SEAL_USE__ADDCARRY_U64)
    mark_as_advanced(SEAL_USE__SUBBORROW_U64)
    mark_as_advanced(SEAL_USE___BUILTIN_CLZLL)
    mark_as_advanced(SEAL_USE___INT128)
endif()

# Build
if(NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/seal)
    if(result)
        message(FATAL_ERROR "Failed to build Microsoft SEAL (${result})")
    endif()
endif()

# Set up the targets
if(NOT MSVC)
    add_subdirectory(
        ${THIRDPARTY_DIR}/seal/src
        ${THIRDPARTY_DIR}/seal/build
        EXCLUDE_FROM_ALL)
endif()

# Microsoft Kuku
# Download and configure
if(NOT MSVC)
    message(STATUS "Setting up Microsoft Kuku ...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/kuku)
    if(result)
        message(FATAL_ERROR "Failed to download Microsoft Kuku (${result})")
    endif()
    mark_as_advanced(KUKU_BUILD_EXAMPLES)
    mark_as_advanced(KUKU_BUILD_KUKU_C)
    mark_as_advanced(KUKU_BUILD_TESTS)
endif()

# Build
if(NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/kuku)
    if(result)
        message(FATAL_ERROR "Failed to build Microsoft Kuku (${result})")
    endif()
endif()

# Set up the targets
if(NOT MSVC)
    add_subdirectory(
        ${THIRDPARTY_DIR}/kuku/src
        ${THIRDPARTY_DIR}/kuku/build
        EXCLUDE_FROM_ALL)
endif()

# FourQ
# This is a fork of https://github.com/microsoft/FourQlib.
# It is built with Makefile.
# Download
if(NOT MSVC)
    message(STATUS "Setting up FourQ ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/fourq)
    else()
        create_cache_entries(${THIRDPARTY_DIR}/fourq)
        if(EXISTS ${THIRDPARTY_DIR}/fourq/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${THIRDPARTY_DIR}/fourq/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/fourq)
    endif()
    if(result)
        message(FATAL_ERROR "Failed to download FourQ (${result})")
    endif()
endif()

# Build
if(NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/fourq)
    if(result)
        message(FATAL_ERROR "Failed to build FourQ (${result})`")
    endif()
endif()

# Set up the targets
# Create imported target for FourQ
if(NOT MSVC)
    add_library(fourq UNKNOWN IMPORTED)
    set_target_properties(fourq PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${THIRDPARTY_DIR}//fourq/src/FourQ_64bit_and_portable
        IMPORTED_LOCATION ${THIRDPARTY_DIR}/fourq/src/FourQ_64bit_and_portable/libFourQ.a)
endif()

# Log4cplus
# Download and configure
if(NOT MSVC)
    message(STATUS "Setting up log4cplus ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/log4cplus)
    else()
        create_cache_entries(${THIRDPARTY_DIR}/log4cplus)
        if(EXISTS ${THIRDPARTY_DIR}/log4cplus/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${THIRDPARTY_DIR}/log4cplus/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/log4cplus)
    endif()
    if(result)
        message(FATAL_ERROR "Failed to download log4cplus (${result})")
    endif()
    mark_as_advanced(ENABLE_SYMBOLS_VISIBILITY)
    mark_as_advanced(LIBADVAPI32)
    mark_as_advanced(LIBCPOSIX)
    mark_as_advanced(LIBICONV)
    mark_as_advanced(LIBKERNEL32)
    mark_as_advanced(LIBNSL)
    mark_as_advanced(LIBPOSIX4)
    mark_as_advanced(LIBRT)
    mark_as_advanced(LIBSOCKET)
    mark_as_advanced(LIBWS2_32)
    set(LOG4CPLUS_BUILD_LOGGINGSERVER OFF CACHE BOOL "" FORCE)
    mark_as_advanced(LOG4CPLUS_BUILD_LOGGINGSERVER)
    set(LOG4CPLUS_BUILD_TESTING OFF CACHE BOOL "" FORCE)
    mark_as_advanced(LOG4CPLUS_BUILD_TESTING)
    set(LOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME OFF CACHE BOOL "" FORCE)
    mark_as_advanced(LOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME)
    mark_as_advanced(LOG4CPLUS_QT4)
    mark_as_advanced(LOG4CPLUS_QT5)
    mark_as_advanced(LOG4CPLUS_REQUIRE_EXPLICIT_INITIALIZATION)
    mark_as_advanced(LOG4CPLUS_SINGLE_THREADED)
    mark_as_advanced(LOG4CPLUS_WORKING_C_LOCALE)
    mark_as_advanced(LOG4CPLUS_WORKING_LOCALE)
    mark_as_advanced(UNICODE)
    mark_as_advanced(WITH_ICONV)
    set(WITH_UNIT_TESTS OFF CACHE BOOL "" FORCE)
    mark_as_advanced(WITH_UNIT_TESTS)
    mark_as_advanced(_WIN32_WINNT)
endif()

# Build
if(NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/log4cplus)
    if(result)
        message(FATAL_ERROR "Failed to build log4cplus (${result})`")
    endif()
endif()

# Set up the targets
if(NOT MSVC)
    add_subdirectory(
        ${THIRDPARTY_DIR}/log4cplus/src
        EXCLUDE_FROM_ALL)
    list(APPEND LOG4CPLUS_INCLUDE_DIRS ${THIRDPARTY_DIR}/log4cplus/src/include)
    set_target_properties(${log4cplus} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${LOG4CPLUS_INCLUDE_DIRS}")
endif()

# Google Test
# This follows the example in
# https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.

# Download and configure
if(APSI_BUILD_TESTS AND NOT MSVC)
    message(STATUS "Setting up Google Test ...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to download Google Test (${result}); disabling `APSI_BUILD_TESTS`")
    endif()
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    mark_as_advanced(BUILD_GMOCK)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(INSTALL_GTEST)
endif()

# Build
if(APSI_BUILD_TESTS AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to build Google Test (${result}); disabling `APSI_BUILD_TESTS`")
    endif()
endif()

# Set up the targets
if(APSI_BUILD_TESTS AND NOT MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(
        ${THIRDPARTY_DIR}/googletest/src
        ${THIRDPARTY_DIR}/googletest/build
        EXCLUDE_FROM_ALL)
endif()

# ZeroMQ and ZeroMQpp
set(ZEROMQ_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindZeroMQ.cmake)
set(ZEROMQPP_FIND_MODULE_PATH ${APSI_SOURCE_DIR}/cmake/FindZeroMQpp.cmake)
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

# FlatBuffers 
# Download and configure
if(NOT MSVC)
    message(STATUS "Setting up flatbuffers ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    else()
        create_cache_entries(${THIRDPARTY_DIR}/flatbuffers)
        if(EXISTS ${THIRDPARTY_DIR}/flatbuffers/build/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${THIRDPARTY_DIR}/flatbuffers/build/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    endif()
    if(result)
        message(FATAL_ERROR "Failed to download flatbuffers (${result})")
    endif()

    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_FLATC ON CACHE BOOL "" FORCE)
    set(FLATBUFFERS_INSTALL OFF CACHE BOOL "" FORCE)
endif()

# Build
if(NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "Failed to build flatbuffers (${result})`")
    endif()

    # flatc executable
    set(FLATBUFFERS_FLATC_PATH "build/flatc")

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi" "${APSI_SOURCE_DIR}/common/native/apsi/psiparams.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/ciphertext.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop_header.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop_response.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()

    execute_process(
        COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/result_package.fbs"
        #OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${THIRDPARTY_DIR}/flatbuffers)
    if(result)
        message(FATAL_ERROR "flatc failed (${result})")
    endif()
endif()

# Set up the targets
if(NOT MSVC)
    add_subdirectory(
        ${THIRDPARTY_DIR}/flatbuffers/src
        EXCLUDE_FROM_ALL)
    list(APPEND FLATBUFFERS_INCLUDE_DIRS ${THIRDPARTY_DIR}/flatbuffers/src/include)
    set_target_properties(${flatbuffers} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${FLATBUFFERS_INCLUDE_DIRS}")
endif()

###########################
# APSI common C++ library #
###########################

# Create an object library to compile sources only once
add_library(common STATIC)

# Add source files to library and header files to install
add_subdirectory(common/native/apsi)

# Set C++ language version and include directories for the object library
apsi_set_language(common)
target_include_directories(common PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)

# Link dependencies
target_link_libraries(common PUBLIC
    seal
    kuku
    ZeroMQ::ZeroMQ
    ZeroMQpp::ZeroMQpp
    fourq
    log4cplus
    flatbuffers)
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

apsi_set_version(common)
set_target_properties(common PROPERTIES OUTPUT_NAME apsi_common-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_link_threads(common)
apsi_install_target(common APSITargets)

if(NOT MSVC)
    apsi_combine_archives(common seal)
    apsi_combine_archives(common log4cplus)
endif()

#############################
# APSI receiver C++ library #
#############################

add_library(receiver STATIC)
add_subdirectory(receiver/native/apsi)
set_target_properties(receiver PROPERTIES OUTPUT_NAME apsi_receiver-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_set_version(receiver)
apsi_link_threads(common)
apsi_set_soversion(receiver)
apsi_set_language(receiver)
target_link_libraries(receiver PUBLIC common)
target_include_directories(receiver PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/receiver/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_link_threads(receiver)
apsi_install_target(receiver APSITargets)

###########################
# APSI sender C++ library #
###########################

add_library(sender STATIC)
add_subdirectory(sender/native/apsi)
set_target_properties(sender PROPERTIES OUTPUT_NAME apsi_sender-${APSI_VERSION_MAJOR}.${APSI_VERSION_MINOR})
apsi_set_version(sender)
apsi_set_soversion(sender)
apsi_set_language(sender)
target_link_libraries(sender PUBLIC common)
target_include_directories(sender PUBLIC
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/sender/native>
    $<BUILD_INTERFACE:${APSI_SOURCE_DIR}/common/native>
    $<INSTALL_INTERFACE:${APSI_INCLUDES_INSTALL_DIR}>)
apsi_link_threads(sender)
apsi_install_target(sender APSITargets)

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
