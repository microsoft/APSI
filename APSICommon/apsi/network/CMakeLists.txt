# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/channel.cpp
		${CMAKE_CURRENT_LIST_DIR}/network_utils.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_utils.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperation.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperationresponse.h
    DESTINATION
        ${APSICOMMON_INCLUDES_INSTALL_DIR}/apsi/network
)
