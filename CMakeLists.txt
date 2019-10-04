cmake_minimum_required(VERSION 3.12)

project(APSI VERSION 1.0.0 LANGUAGES CXX C)

if (DEFINED MSVC)
    message(FATAL_ERROR "Please build APSI using the attached Visual Studio solution/project file")
endif()

# Build in release mode by default
set(APSI_DEFAULT_BUILD_TYPE "Release")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${APSI_DEFAULT_BUILD_TYPE} CACHE
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
message(STATUS "APSI debug mode: ${APSI_DEBUG}")

# For finding local configuration files without installing
list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_SOURCE_DIR}/APSICommon/cmake
    ${CMAKE_SOURCE_DIR}/APSISender/cmake
    ${CMAKE_SOURCE_DIR}/APSIReceiver/cmake)

add_subdirectory(APSICommon)
add_subdirectory(APSISender)
add_subdirectory(APSIReceiver)

if(BUILD_TESTS)
    # Only build GTest
    option(BUILD_GMOCK OFF)
    option(INSTALL_GTEST OFF)
    mark_as_advanced(BUILD_GMOCK INSTALL_GTEST)

    # Add GTest
    set(GTEST_DIR "${CMAKE_CURRENT_LIST_DIR}/thirdparty/googletest")
    if(NOT EXISTS ${GTEST_DIR}/CMakeLists.txt)
        message(FATAL_ERROR "Could not find `${GTEST_DIR}/CMakeLists.txt`. Run `git submodule update --init` and retry.")
    endif()

    add_subdirectory(${GTEST_DIR})
    add_subdirectory(APSITests)
    add_subdirectory(IntegrationTests)
endif()

add_subdirectory(CommonCodeCLI)
add_subdirectory(SenderCLI)
add_subdirectory(ReceiverCLI)
