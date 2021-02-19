# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter.cpp
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter_table.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter.h
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter_table.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
