# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(receiver
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/plaintext_powers.cpp
        ${CMAKE_CURRENT_LIST_DIR}/receiver.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/itt.h
        ${CMAKE_CURRENT_LIST_DIR}/match_record.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver.h
    DESTINATION
        ${PROJECT_INCLUDES_INSTALL_DIR}/apsi
)
