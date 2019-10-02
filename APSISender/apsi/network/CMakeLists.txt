# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/senderchannel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/senderchannel.h
    DESTINATION
        ${APSISENDER_INCLUDES_INSTALL_DIR}/apsi/network
)
