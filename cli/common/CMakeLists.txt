# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(common_cli
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/common_utils.cpp
        ${CMAKE_CURRENT_LIST_DIR}/csv_reader.cpp
)
