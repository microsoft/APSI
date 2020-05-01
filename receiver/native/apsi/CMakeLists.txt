# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(receiver
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/receiver.cpp
)

add_subdirectory(network)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/receiver.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
