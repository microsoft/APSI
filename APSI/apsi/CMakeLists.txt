# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/apsidefines.cpp
		${CMAKE_CURRENT_LIST_DIR}/item.cpp
		${CMAKE_CURRENT_LIST_DIR}/plaintextarith.cpp
)

add_subdirectory(ffield)
add_subdirectory(logging)
add_subdirectory(network)
add_subdirectory(receiver)
add_subdirectory(sender)
add_subdirectory(tools)
