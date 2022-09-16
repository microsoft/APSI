# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/csv_reader.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
        ${CMAKE_CURRENT_LIST_DIR}/base_clp.h
        ${CMAKE_CURRENT_LIST_DIR}/common_utils.h
        ${CMAKE_CURRENT_LIST_DIR}/csv_reader.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi/util
)

set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
