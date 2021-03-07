# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi/util
)
