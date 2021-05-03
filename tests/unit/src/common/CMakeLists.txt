# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
        ${CMAKE_CURRENT_LIST_DIR}/item.cpp
        ${CMAKE_CURRENT_LIST_DIR}/oprf.cpp
        ${CMAKE_CURRENT_LIST_DIR}/powers.cpp
        ${CMAKE_CURRENT_LIST_DIR}/psi_params.cpp
        ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation_response.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()
