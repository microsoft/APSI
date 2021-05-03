# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.cpp
    ${CMAKE_CURRENT_LIST_DIR}/query.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sender_db.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.h
        ${CMAKE_CURRENT_LIST_DIR}/query.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
        ${CMAKE_CURRENT_LIST_DIR}/sender_db.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)

add_subdirectory(util)

if(APSI_USE_ZMQ)
    add_subdirectory(zmq)
endif()
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
