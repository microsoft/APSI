# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/consts.c
        ${CMAKE_CURRENT_LIST_DIR}/fp2_1271_AVX2.S
        ${CMAKE_CURRENT_LIST_DIR}/fp2_1271.S
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_x64.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/fourq/amd64
)