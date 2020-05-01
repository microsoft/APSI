# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/network_channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/network_utils.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_utils.h
    ${CMAKE_CURRENT_LIST_DIR}/network_channel.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperation.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperationresponse.h
    ${CMAKE_CURRENT_LIST_DIR}/stream_channel.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/network
)
