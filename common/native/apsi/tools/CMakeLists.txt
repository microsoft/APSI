# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/csvreader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sealcompress.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/csvreader.h
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/matrix.h
        ${CMAKE_CURRENT_LIST_DIR}/matrixview.h
        ${CMAKE_CURRENT_LIST_DIR}/sealcompress.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/tools
)
