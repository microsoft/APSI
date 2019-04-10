# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/dbblock.cpp
		${CMAKE_CURRENT_LIST_DIR}/sender.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderdb.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderdispatcher.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/dbblock.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
        ${CMAKE_CURRENT_LIST_DIR}/senderdb.h
        ${CMAKE_CURRENT_LIST_DIR}/senderdispatcher.h
        ${CMAKE_CURRENT_LIST_DIR}/sendersessioncontext.h
        ${CMAKE_CURRENT_LIST_DIR}/senderthreadcontext.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
