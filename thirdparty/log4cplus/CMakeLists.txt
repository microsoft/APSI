# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(LOG4CPLUS_DOWNLOAD VERSION 2.0.5)

if(MSVC)
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build/${LOG4CPLUS_PLATFORM})
else()
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
endif()

set(LOG4CPLUS_CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLOG4CPLUS_BUILD_LOGGINGSERVER=OFF -DLOG4CPLUS_BUILD_TESTING=OFF -DLOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME=OFF -DSKIP_INSTALL_ALL=ON -DWITH_UNIT_TESTS=OFF)
if(EXISTS cache_init.txt)
    set(LOG4CPLUS_CMAKE_ARGS ${LOG4CPLUS_CMAKE_ARGS} -C../cache_init.txt)
endif()

include(ExternalProject)
ExternalProject_Add(EP_LOG4CPLUS
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${TEMP_BINARY_DIR}
    GIT_REPOSITORY      git@github.com:log4cplus/log4cplus.git
    GIT_TAG             REL_${PROJECT_VERSION_MAJOR}_${PROJECT_VERSION_MINOR}_${PROJECT_VERSION_PATCH}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          ${LOG4CPLUS_CMAKE_ARGS}
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
