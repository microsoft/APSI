# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
        ${CMAKE_CURRENT_LIST_DIR}/channel_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/csvreader_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/interpolate_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/item.cpp
        ${CMAKE_CURRENT_LIST_DIR}/matrix_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/oprf_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/unit_tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils_tests.cpp
)
