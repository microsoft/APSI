# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(LOG4CPLUS_DOWNLOAD VERSION 2.0.5)

if(MSVC)
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build/${LOG4CPLUS_PLATFORM})
else()
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
endif()

if(EXISTS cache_init.txt)
    set(LOG4CPLUS_CMAKE_ARGS "-C../cache_init.txt")
else()
    set(LOG4CPLUS_CMAKE_ARGS "")
endif()

# The tag format for Log4cplus is `REL_major_minor_patch`
string(REPLACE "." "_" LOG4CPLUS_TAG_VERSION ${PROJECT_VERSION})

include(ExternalProject)
ExternalProject_Add(EP_LOG4CPLUS
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${TEMP_BINARY_DIR}
    GIT_REPOSITORY      https://github.com/log4cplus/log4cplus.git
    GIT_TAG             REL_${LOG4CPLUS_TAG_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          ${LOG4CPLUS_CMAKE_ARGS}
    CMAKE_CACHE_ARGS    -DCMAKE_BUILD_TYPE:STRING=Release -DBUILD_SHARED_LIBS:BOOL=OFF -DLOG4CPLUS_BUILD_LOGGINGSERVER:BOOL=OFF -DLOG4CPLUS_BUILD_TESTING:BOOL=OFF -DLOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME:BOOL=OFF -DWITH_UNIT_TESTS:BOOL=OFF
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
