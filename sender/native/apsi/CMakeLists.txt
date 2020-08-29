# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/binbundle.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/senderdb.cpp
)

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/binbundle.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
        ${CMAKE_CURRENT_LIST_DIR}/senderdb.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
