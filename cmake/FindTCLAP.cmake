# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate TCLAP
if(NOT TARGET TCLAP)
    set(CURRENT_TCLAP_INCLUDE_DIR ${TCLAP_INCLUDE_DIR})
    unset(TCLAP_INCLUDE_DIR CACHE)
    find_path(TCLAP_INCLUDE_DIR
        NAMES tclap/CmdLine.h
        HINTS ${CURRENT_TCLAP_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(TCLAP
        REQUIRED_VARS TCLAP_INCLUDE_DIR)

    if(TCLAP_FOUND)
        # Create interface target for TCLAP
        add_library(TCLAP INTERFACE)
        set_target_properties(TCLAP PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${TCLAP_INCLUDE_DIR})
    endif()
endif()
