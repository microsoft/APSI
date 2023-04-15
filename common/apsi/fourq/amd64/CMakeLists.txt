# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
if(APSI_USE_ASM)
    if(APSI_USE_AVX2)
        set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
            ${CMAKE_CURRENT_LIST_DIR}/consts.c
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271_AVX2.S
        )
    else()
        set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271.S
        )
    endif()
endif()

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_x64.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq/amd64
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
