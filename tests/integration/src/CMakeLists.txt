# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(integration_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/integration_tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_sender_receiver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/test_utils.cpp
)

target_include_directories(integration_tests PRIVATE ${CMAKE_CURRENT_LIST_DIR})

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()
