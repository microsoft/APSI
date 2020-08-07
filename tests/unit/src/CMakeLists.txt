# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
        ${CMAKE_CURRENT_LIST_DIR}/channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/csvreader.cpp
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
        ${CMAKE_CURRENT_LIST_DIR}/item.cpp
        ${CMAKE_CURRENT_LIST_DIR}/oprf.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/unit_tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)
