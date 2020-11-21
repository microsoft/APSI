# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(ZEROMQ_INCLUDE_DIR NAMES zmq.h)
find_library(ZEROMQ_LIBRARY_PATH NAMES zmq)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(ZeroMQ
    REQUIRED_VARS ZEROMQ_INCLUDE_DIR ZEROMQ_LIBRARY_PATH)

if(ZeroMQ_FOUND AND NOT TARGET ZeroMQ::ZeroMQ)
    get_filename_component(ZEROMQ_LIBRARY_DIR ${ZEROMQ_LIBRARY_PATH} DIRECTORY CACHE)

    # Create imported target for ZeroMQ
    add_library(ZeroMQ::ZeroMQ UNKNOWN IMPORTED)
    set_target_properties(ZeroMQ::ZeroMQ PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${ZEROMQ_INCLUDE_DIR}
        IMPORTED_LOCATION ${ZEROMQ_LIBRARY_PATH})
endif()
