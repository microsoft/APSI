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
set(CMAKE_PREFIX_PATH ${CMAKE_SOURCE_DIR}/APSICommon ${CMAKE_SOURCE_DIR}/APSISender ${CMAKE_SOURCE_DIR}/APSIReceiver)

add_subdirectory(APSICommon)
add_subdirectory(APSISender)
add_subdirectory(APSIReceiver)
