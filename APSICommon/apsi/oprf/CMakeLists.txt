# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ecpoint.cpp
        ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/ecpoint.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_common.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.h
    DESTINATION
        ${APSICOMMON_INCLUDES_INSTALL_DIR}/apsi/oprf
)
