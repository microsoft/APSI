# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/sender_dispatcher.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/sender_dispatcher.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/zmq
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
