# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/aes.cpp
		${CMAKE_CURRENT_LIST_DIR}/bigpoly.cpp
		${CMAKE_CURRENT_LIST_DIR}/bigpolyarray.cpp
		${CMAKE_CURRENT_LIST_DIR}/csvreader.cpp
		${CMAKE_CURRENT_LIST_DIR}/fourq.cpp
		${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
		${CMAKE_CURRENT_LIST_DIR}/nussbaumer.cpp
		${CMAKE_CURRENT_LIST_DIR}/polyfftmultsmallmod.cpp
		${CMAKE_CURRENT_LIST_DIR}/polymodulus.cpp
		${CMAKE_CURRENT_LIST_DIR}/prng.cpp
		${CMAKE_CURRENT_LIST_DIR}/sealcompress.cpp
		${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
		${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/aes.h
        ${CMAKE_CURRENT_LIST_DIR}/bigpoly.h
        ${CMAKE_CURRENT_LIST_DIR}/bigpolyarray.h
        ${CMAKE_CURRENT_LIST_DIR}/csvreader.h
        ${CMAKE_CURRENT_LIST_DIR}/fourq.h
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/matrix.h
        ${CMAKE_CURRENT_LIST_DIR}/matrixview.h
        ${CMAKE_CURRENT_LIST_DIR}/nussbaumer.h
        ${CMAKE_CURRENT_LIST_DIR}/polyfftmultsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/polymodulus.h
        ${CMAKE_CURRENT_LIST_DIR}/prng.h
        ${CMAKE_CURRENT_LIST_DIR}/sealcompress.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
