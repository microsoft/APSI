# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/apsidefines.cpp
        ${CMAKE_CURRENT_LIST_DIR}/item.cpp
)

add_subdirectory(ffield)
add_subdirectory(logging)
add_subdirectory(network)
add_subdirectory(tools)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/apsidefines.h
        ${CMAKE_CURRENT_LIST_DIR}/apsi.h
        ${CMAKE_CURRENT_LIST_DIR}/item.h
        ${CMAKE_CURRENT_LIST_DIR}/psiparams.h
        ${CMAKE_CURRENT_LIST_DIR}/result_package.h
    DESTINATION
        ${APSICOMMON_INCLUDES_INSTALL_DIR}/apsi
)
