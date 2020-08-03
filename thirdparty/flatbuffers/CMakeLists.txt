# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(FBS_DOWNLOAD VERSION 1.12.0)

include(ExternalProject)
ExternalProject_Add(EP_FBS
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY      https://github.com/google/flatbuffers.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATC=ON -DFLATBUFFERS_INSTALL=OFF
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
