# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/ecpoint.cpp
    ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.cpp
    ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/ecpoint.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_common.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.h
        ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/oprf
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
