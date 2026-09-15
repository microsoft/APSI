# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Mirror the header into the build tree under apsi/fourq/ARM64/ so that includes like
# "apsi/fourq/ARM64/fp_arm64.h" resolve via the public include path
# ${CMAKE_BINARY_DIR}/common.
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
    ${CMAKE_BINARY_DIR}/common/apsi/fourq/ARM64/fp_arm64.h
    COPYONLY)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_arm64.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/ARM64
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
