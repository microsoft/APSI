# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi_common
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/aes.cpp
		${CMAKE_CURRENT_LIST_DIR}/bigpoly.cpp
		${CMAKE_CURRENT_LIST_DIR}/csvreader.cpp
		${CMAKE_CURRENT_LIST_DIR}/fourq.cpp
		${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
		${CMAKE_CURRENT_LIST_DIR}/prng.cpp
		${CMAKE_CURRENT_LIST_DIR}/sealcompress.cpp
		${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
		${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/aes.h
        ${CMAKE_CURRENT_LIST_DIR}/bigpoly.h
        ${CMAKE_CURRENT_LIST_DIR}/csvreader.h
        ${CMAKE_CURRENT_LIST_DIR}/fourq.h
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/matrix.h
        ${CMAKE_CURRENT_LIST_DIR}/matrixview.h
        ${CMAKE_CURRENT_LIST_DIR}/prng.h
        ${CMAKE_CURRENT_LIST_DIR}/sealcompress.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
