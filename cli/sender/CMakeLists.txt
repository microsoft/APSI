# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender_cli
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_utils.cpp
)
