# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Mirror generic header into the build tree under apsi/fourq/generic/ so includes like
# "apsi/fourq/generic/fp.h" resolve via the public include path
# ${CMAKE_BINARY_DIR}/common.
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/fp.h
    ${CMAKE_BINARY_DIR}/common/apsi/fourq/generic/fp.h
    COPYONLY)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/generic
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
