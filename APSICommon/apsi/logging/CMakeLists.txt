# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/log.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/log.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
