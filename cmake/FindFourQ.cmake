# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate FourQ
if(NOT TARGET FourQ)
    set(CURRENT_FOURQ_INCLUDE_DIR ${FOURQ_INCLUDE_DIR})
    set(CURRENT_FOURQ_LIBRARY_DIR ${FOURQ_LIBRARY_DIR})
    set(CURRENT_FOURQ_LIBRARY_PATH ${FOURQ_LIBRARY_PATH})

    unset(FOURQ_INCLUDE_DIR CACHE)
    find_path(FOURQ_INCLUDE_DIR
        NAMES FourQ.h
        HINTS ${CURRENT_FOURQ_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    unset(FOURQ_LIBRARY_DIR CACHE)
    unset(FOURQ_LIBRARY_PATH CACHE)
    find_library(FOURQ_LIBRARY_PATH
        NAMES FourQ
        HINTS ${CURRENT_FOURQ_LIBRARY_DIR} ${FOURQ_INCLUDE_DIR} ${CMAKE_LIBRARY_PATH})
    if(FOURQ_LIBRARY_PATH)
        get_filename_component(FOURQ_LIBRARY_DIR ${FOURQ_LIBRARY_PATH} DIRECTORY CACHE)
    endif()

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(FourQ
        REQUIRED_VARS FOURQ_INCLUDE_DIR FOURQ_LIBRARY_DIR FOURQ_LIBRARY_PATH)

    if(FourQ_FOUND)
        # Create interface target for FourQ
        add_library(FourQ UNKNOWN IMPORTED)

        set_target_properties(FourQ PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${FOURQ_INCLUDE_DIR}
            IMPORTED_LOCATION ${FOURQ_LIBRARY_PATH})
    endif()
endif()
