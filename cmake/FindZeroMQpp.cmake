# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate ZeroMQpp
if(NOT TARGET ZeroMQpp)
    set(CURRENT_ZEROMQPP_INCLUDE_DIR ${ZEROMQPP_INCLUDE_DIR})
    set(CURRENT_ZEROMQPP_LIBRARY_DIR ${ZEROMQPP_LIBRARY_DIR})
    set(CURRENT_ZEROMQPP_LIBRARY_PATH ${ZEROMQPP_LIBRARY_PATH})

    unset(ZEROMQPP_INCLUDE_DIR CACHE)
    find_path(ZEROMQPP_INCLUDE_DIR
        NAMES zmqpp/zmqpp.hpp
        HINTS ${CURRENT_ZEROMQPP_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    unset(ZEROMQPP_LIBRARY_DIR CACHE)
    unset(ZEROMQPP_LIBRARY_PATH CACHE)
    find_library(ZEROMQPP_LIBRARY_PATH
        NAMES zmqpp
        HINTS ${CURRENT_ZEROMQPP_LIBRARY_DIR} ${CMAKE_LIBRARY_PATH})
    if(ZEROMQPP_LIBRARY_PATH)
        get_filename_component(ZEROMQPP_LIBRARY_DIR ${ZEROMQPP_LIBRARY_PATH} DIRECTORY CACHE)
    endif()

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(ZeroMQpp
        REQUIRED_VARS ZEROMQPP_INCLUDE_DIR ZEROMQPP_LIBRARY_DIR ZEROMQPP_LIBRARY_PATH)

    if(ZeroMQpp_FOUND)
        # Create interface target for ZeroMQpp
        add_library(ZeroMQpp UNKNOWN IMPORTED)

        set_target_properties(ZeroMQpp PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${ZEROMQPP_INCLUDE_DIR}
            IMPORTED_LOCATION ${ZEROMQPP_LIBRARY_PATH})
    endif()
endif()
