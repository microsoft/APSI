# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sender_operation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sender_operation_response.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_channel.h
        ${CMAKE_CURRENT_LIST_DIR}/result_package.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_operation_response.h
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/network
)

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
