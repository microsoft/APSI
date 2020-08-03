# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/network_channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation_response.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_channel.h
        ${CMAKE_CURRENT_LIST_DIR}/result_package.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation_response.h
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/network
)
