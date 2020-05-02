# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(FOURQ_INCLUDE_DIR NAMES FourQ/FourQ.h)
find_library(FOURQ_LIBRARY_PATH NAMES FourQ)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(FourQ
    REQUIRED_VARS FOURQ_INCLUDE_DIR FOURQ_LIBRARY_PATH)

if(FourQ_FOUND AND NOT TARGET FourQ::FourQ)
    get_filename_component(FOURQ_LIBRARY_DIR ${FOURQ_LIBRARY_PATH} DIRECTORY CACHE)

    # Create imported target for FourQ
    add_library(FourQ::FourQ UNKNOWN IMPORTED)
    set_target_properties(FourQ::FourQ PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${FOURQ_INCLUDE_DIR}
        IMPORTED_LOCATION ${FOURQ_LIBRARY_PATH})
endif()
