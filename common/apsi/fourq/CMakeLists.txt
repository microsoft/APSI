# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/crypto_util.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_core.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_no_endo.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2.c
    ${CMAKE_CURRENT_LIST_DIR}/hash_to_curve.c
    ${CMAKE_CURRENT_LIST_DIR}/random.c
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_api.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_internal.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_params.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_tables.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ.h
        ${CMAKE_CURRENT_LIST_DIR}/table_lookup.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/fourq
)

if(APSI_FOURQ_AMD64)
    add_subdirectory(amd64)
elseif(APSI_FOURQ_ARM64)
    add_subdirectory(arm64)
else()
    add_subdirectory(generic)
endif()
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
