# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/crypto_util.c
        ${CMAKE_CURRENT_LIST_DIR}/eccp2_core.c
        ${CMAKE_CURRENT_LIST_DIR}/eccp2_no_endo.c
        ${CMAKE_CURRENT_LIST_DIR}/eccp2.c
        ${CMAKE_CURRENT_LIST_DIR}/hash_to_curve.c
        ${CMAKE_CURRENT_LIST_DIR}/kex.c
        ${CMAKE_CURRENT_LIST_DIR}/random.c
        ${CMAKE_CURRENT_LIST_DIR}/sha512.c
)

add_subdirectory(amd64)
add_subdirectory(arm64)
add_subdirectory(generic)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_api.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_internal.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_params.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ_tables.h
        ${CMAKE_CURRENT_LIST_DIR}/FourQ.h
        ${CMAKE_CURRENT_LIST_DIR}/table_lookup.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/fourq
)
