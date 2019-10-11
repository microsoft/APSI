# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(Common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/log.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/log.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/logging
)
