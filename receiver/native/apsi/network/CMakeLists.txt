# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(receiver
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/receiverchannel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/receiverchannel.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/network
)
