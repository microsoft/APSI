# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate Flint
if(NOT TARGET Flint)
    set(CURRENT_FLINT_INCLUDE_DIR ${FLINT_INCLUDE_DIR})
    set(CURRENT_FLINT_LIBRARY_DIR ${FLINT_LIBRARY_DIR})
    set(CURRENT_FLINT_LIBRARY_PATH ${FLINT_LIBRARY_PATH})

    unset(FLINT_INCLUDE_DIR CACHE)
    find_path(FLINT_INCLUDE_DIR
        NAMES flint/flint.h flint/fmpq.h flint/fmpz.h
        HINTS ${CURRENT_FLINT_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    unset(FLINT_LIBRARY_DIR CACHE)
    unset(FLINT_LIBRARY_PATH CACHE)
    find_library(FLINT_LIBRARY_PATH
        NAMES flint
    _   HINTS ${CURRENT_FLINT_LIBRARY_DIR} ${CMAKE_LIBRARY_PATH})
    if(FLINT_LIBRARY_PATH)
        get_filename_component(FLINT_LIBRARY_DIR ${FLINT_LIBRARY_PATH} DIRECTORY CACHE)
    endif()

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(Flint
        REQUIRED_VARS FLINT_INCLUDE_DIR FLINT_LIBRARY_DIR FLINT_LIBRARY_PATH)

    if(Flint_FOUND)
        # Create imported target for Flint
        add_library(Flint UNKNOWN IMPORTED)

        set_target_properties(Flint PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${FLINT_INCLUDE_DIR}
            IMPORTED_LOCATION ${FLINT_LIBRARY_PATH})
    endif()
endif()
