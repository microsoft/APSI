# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/generic
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
