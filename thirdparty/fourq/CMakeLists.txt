# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(FOURQ_DOWNLOAD VERSION 2.0.5)

include(ExternalProject)
ExternalProject_Add(EP_FOURQ
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    GIT_REPOSITORY      https://github.com/kiromaru/FourQlib.git
    CONFIGURE_COMMAND   ""
    BUILD_IN_SOURCE     TRUE
    BUILD_COMMAND       make -C FourQ_64bit_and_portable/ static
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
