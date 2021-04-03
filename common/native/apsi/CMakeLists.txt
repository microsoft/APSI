# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/item.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/powers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/psi_params.cpp
    ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.cpp
    ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/apsi.h
        ${CMAKE_CURRENT_LIST_DIR}/crypto_context.h
        ${CMAKE_CURRENT_LIST_DIR}/item.h
        ${CMAKE_CURRENT_LIST_DIR}/log.h
        ${CMAKE_CURRENT_LIST_DIR}/powers.h
        ${CMAKE_CURRENT_LIST_DIR}/psi_params.h
        ${CMAKE_CURRENT_LIST_DIR}/requests.h
        ${CMAKE_CURRENT_LIST_DIR}/responses.h
        ${CMAKE_CURRENT_LIST_DIR}/seal_object.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.h
        ${CMAKE_CURRENT_LIST_DIR}/version.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)

add_subdirectory(fourq)
add_subdirectory(network)
add_subdirectory(oprf)
add_subdirectory(util)
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
