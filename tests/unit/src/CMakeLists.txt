# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/unit_tests_runner.cpp
)

add_subdirectory(common)
add_subdirectory(receiver)
add_subdirectory(sender)
