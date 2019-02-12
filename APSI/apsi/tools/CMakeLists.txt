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

