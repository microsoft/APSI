# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/receiver.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/receiver.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
