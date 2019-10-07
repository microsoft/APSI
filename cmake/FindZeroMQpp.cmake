# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(ZEROMQPP_INCLUDE_DIR NAMES zmqpp/zmqpp.hpp)
find_library(ZEROMQPP_LIBRARY_PATH NAMES zmqpp)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(ZeroMQpp
    REQUIRED_VARS ZEROMQPP_INCLUDE_DIR ZEROMQPP_LIBRARY_PATH)

if(ZeroMQpp_FOUND AND NOT TARGET ZeroMQpp::ZeroMQpp)
    get_filename_component(ZEROMQPP_LIBRARY_DIR ${ZEROMQPP_LIBRARY_PATH} DIRECTORY CACHE)

    # Create imported target for ZeroMQPP
    add_library(ZeroMQpp::ZeroMQpp UNKNOWN IMPORTED)
    set_target_properties(ZeroMQpp::ZeroMQpp PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${ZEROMQPP_INCLUDE_DIR}
        IMPORTED_LOCATION ${ZEROMQPP_LIBRARY_PATH})
endif()
