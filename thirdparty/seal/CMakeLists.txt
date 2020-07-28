# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEAL_DOWNLOAD VERSION 3.5.6)

include(ExternalProject)
ExternalProject_Add(EP_SEAL
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    GIT_REPOSITORY      https://github.com/microsoft/SEAL.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
