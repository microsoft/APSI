# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/zmq_channel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/zmq_channel.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/network/zmq
)
