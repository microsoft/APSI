# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/fourq/arm64
)