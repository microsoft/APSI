# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(LOG4CPLUS_INCLUDE_DIR NAMES log4cplus/logger.h)
find_library(LOG4CPLUS_LIBRARY_PATH NAMES log4cplus)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(Log4cplus
    REQUIRED_VARS LOG4CPLUS_INCLUDE_DIR LOG4CPLUS_LIBRARY_PATH)

if(Log4cplus_FOUND AND NOT TARGET Log4cplus::Log4cplus)
    get_filename_component(LOG4CPLUS_LIBRARY_DIR ${LOG4CPLUS_LIBRARY_PATH} DIRECTORY CACHE)

    # Create imported target for Log4cplus
    add_library(Log4cplus::Log4cplus UNKNOWN IMPORTED)
    set_target_properties(Log4cplus::Log4cplus PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${LOG4CPLUS_INCLUDE_DIR}
        IMPORTED_LOCATION ${LOG4CPLUS_LIBRARY_PATH})
endif()
