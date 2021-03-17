# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_COMMON_SOURCE_FILES ${APSI_COMMON_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h # TODO: mistake?
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/arm64
)

set(APSI_COMMON_SOURCE_FILES ${APSI_COMMON_SOURCE_FILES} PARENT_SCOPE)