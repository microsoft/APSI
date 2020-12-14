# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.cpp
        ${CMAKE_CURRENT_LIST_DIR}/query.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender_db.cpp
)

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.h
        ${CMAKE_CURRENT_LIST_DIR}/query.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_db.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
