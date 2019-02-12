# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/dbblock.cpp
		${CMAKE_CURRENT_LIST_DIR}/sender.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderdb.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderdispatcher.cpp
)

