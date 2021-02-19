# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_db.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)
