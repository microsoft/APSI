# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(integration_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/zmq_sender_receiver.cpp
)
