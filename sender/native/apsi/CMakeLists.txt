# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/binbundle.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
        ${CMAKE_CURRENT_LIST_DIR}/senderdb.cpp
        ${CMAKE_CURRENT_LIST_DIR}/senderdispatcher.cpp
)

add_subdirectory(network)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/binbundle.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
        ${CMAKE_CURRENT_LIST_DIR}/senderdb.h
        ${CMAKE_CURRENT_LIST_DIR}/senderdispatcher.h
        ${CMAKE_CURRENT_LIST_DIR}/senderthreadcontext.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
