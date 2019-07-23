# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate GMP
set(CURRENT_GMP_INCLUDE_DIR ${GMP_INCLUDE_DIR})
set(CURRENT_GMP_LIBRARY_DIR ${GMP_LIBRARY_DIR})
set(CURRENT_GMP_LIBRARY_PATH ${GMP_LIBRARY_PATH})

unset(GMP_INCLUDE_DIR CACHE)
find_path(GMP_INCLUDE_DIR
    NAMES gmp.h
    HINTS ${CURRENT_GMP_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

unset(GMP_LIBRARY_DIR CACHE)
unset(GMP_LIBRARY_PATH CACHE)
find_library(GMP_LIBRARY_PATH
    NAMES gmp
_   HINTS ${CURRENT_GMP_LIBRARY_DIR} ${CMAKE_LIBRARY_PATH})
if(GMP_LIBRARY_PATH)
    get_filename_component(GMP_LIBRARY_DIR ${GMP_LIBRARY_PATH} DIRECTORY CACHE)
endif()

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(GMP
    REQUIRED_VARS GMP_INCLUDE_DIR GMP_LIBRARY_DIR GMP_LIBRARY_PATH)

if(GMP_FOUND)
    # Create imported target for GMP
    add_library(GMP UNKNOWN IMPORTED)

    set_target_properties(GMP PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
        IMPORTED_LOCATION ${GMP_LIBRARY_PATH})
endif()
