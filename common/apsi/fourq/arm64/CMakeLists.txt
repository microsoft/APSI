# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/arm64
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
