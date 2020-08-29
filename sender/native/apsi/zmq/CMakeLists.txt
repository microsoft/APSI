# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sender_dispatcher.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/sender_dispatcher.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
