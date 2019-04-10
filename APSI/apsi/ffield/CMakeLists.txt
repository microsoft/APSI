# Copyright (c) Microsfot Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/ffield.cpp
		${CMAKE_CURRENT_LIST_DIR}/ffield_elt.cpp
		${CMAKE_CURRENT_LIST_DIR}/ffield_fast_batch_encoder.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/ffield_array.h
        ${CMAKE_CURRENT_LIST_DIR}/ffield_elt.h
        ${CMAKE_CURRENT_LIST_DIR}/ffield_fast_batch_encoder.h
        ${CMAKE_CURRENT_LIST_DIR}/ffield.h
    DESTINATION
        ${APSI_INCLUDES_INSTALL_DIR}/apsi
)
