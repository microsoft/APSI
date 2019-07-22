# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/blake2b.c
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/blake2b-load-sse2.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2b-load-sse41.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2b-round.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2b-config.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2-impl.h
    DESTINATION
        ${APSICOMMON_INCLUDES_INSTALL_DIR}/apsi/tools/blake2
)
