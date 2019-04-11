# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/channel.cpp
		${CMAKE_CURRENT_LIST_DIR}/network_utils.cpp
		${CMAKE_CURRENT_LIST_DIR}/receiverchannel.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderchannel.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_utils.h
        ${CMAKE_CURRENT_LIST_DIR}/receiverchannel.h
        ${CMAKE_CURRENT_LIST_DIR}/senderchannel.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperation.h
        ${CMAKE_CURRENT_LIST_DIR}/senderoperationresponse.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
