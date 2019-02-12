# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(apsi
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/channel.cpp
		${CMAKE_CURRENT_LIST_DIR}/network_utils.cpp
		${CMAKE_CURRENT_LIST_DIR}/receiverchannel.cpp
		${CMAKE_CURRENT_LIST_DIR}/senderchannel.cpp
)

