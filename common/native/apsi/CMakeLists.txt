# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/psiparams.cpp
)

# Create the config file
configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_LIST_DIR}/config.h)

add_subdirectory(logging)
add_subdirectory(network)
add_subdirectory(util)
add_subdirectory(oprf)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/apsi.h
        ${CMAKE_CURRENT_LIST_DIR}/config.h
        ${CMAKE_CURRENT_LIST_DIR}/cryptocontext.h
        ${CMAKE_CURRENT_LIST_DIR}/item.h
        ${CMAKE_CURRENT_LIST_DIR}/psiparams.h
        ${CMAKE_CURRENT_LIST_DIR}/sealobject.h
        ${CMAKE_CURRENT_LIST_DIR}/version.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
