# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate ZeroMQ
if(NOT TARGET ZeroMQ)
    set(CURRENT_ZEROMQ_INCLUDE_DIR ${ZEROMQ_INCLUDE_DIR})
    set(CURRENT_ZEROMQ_LIBRARY_DIR ${ZEROMQ_LIBRARY_DIR})
    set(CURRENT_ZEROMQ_LIBRARY_PATH ${ZEROMQ_LIBRARY_PATH})

    unset(ZEROMQ_INCLUDE_DIR CACHE)
    find_path(ZEROMQ_INCLUDE_DIR
        NAMES zmq.h
        HINTS ${CURRENT_ZEROMQ_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    unset(ZEROMQ_LIBRARY_DIR CACHE)
    unset(ZEROMQ_LIBRARY_PATH CACHE)
    find_library(ZEROMQ_LIBRARY_PATH
        NAMES zmq
        HINTS ${CURRENT_ZEROMQ_LIBRARY_DIR} ${CMAKE_LIBRARY_PATH})
    if(ZEROMQ_LIBRARY_PATH)
        get_filename_component(ZEROMQ_LIBRARY_DIR ${ZEROMQ_LIBRARY_PATH} DIRECTORY CACHE)
    endif()

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(ZeroMQ
        REQUIRED_VARS ZEROMQ_INCLUDE_DIR ZEROMQ_LIBRARY_DIR ZEROMQ_LIBRARY_PATH)

    if(ZeroMQ_FOUND)
        # Create interface target for ZeroMQ
        add_library(ZeroMQ UNKNOWN IMPORTED)

        set_target_properties(ZeroMQ PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${ZEROMQ_INCLUDE_DIR}
            IMPORTED_LOCATION ${ZEROMQ_LIBRARY_PATH})
    endif()
endif()
