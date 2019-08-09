# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate Log4cplus
if(NOT TARGET Log4cplus)
    set(CURRENT_LOG4CPLUS_INCLUDE_DIR ${LOG4CPLUS_INCLUDE_DIR})
    set(CURRENT_LOG4CPLUS_LIBRARY_DIR ${LOG4CPLUS_LIBRARY_DIR})
    set(CURRENT_LOG4CPLUS_LIBRARY_PATH ${LOG4CPLUS_LIBRARY_PATH})

    unset(LOG4CPLUS_INCLUDE_DIR CACHE)
    find_path(LOG4CPLUS_INCLUDE_DIR
        NAMES log4cplus/logger.h
        HINTS ${CURRENT_LOG4CPLUS_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

    unset(LOG4CPLUS_LIBRARY_DIR CACHE)
    unset(LOG4CPLUS_LIBRARY_PATH CACHE)
    find_library(LOG4CPLUS_LIBRARY_PATH
        NAMES log4cplus
        HINTS ${CURRENT_LOG4CPLUS_LIBRARY_DIR} ${CMAKE_LIBRARY_PATH})
    if(LOG4CPLUS_LIBRARY_PATH)
        get_filename_component(LOG4CPLUS_LIBRARY_DIR ${LOG4CPLUS_LIBRARY_PATH} DIRECTORY CACHE)
    endif()

    find_package(PackageHandleStandardArgs)
    find_package_handle_standard_args(Log4cplus
        REQUIRED_VARS LOG4CPLUS_INCLUDE_DIR LOG4CPLUS_LIBRARY_DIR LOG4CPLUS_LIBRARY_PATH)

    if(Log4cplus_FOUND)
        # Create interface target for Log4cplus
        add_library(Log4cplus UNKNOWN IMPORTED)

        set_target_properties(Log4cplus PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES ${LOG4CPLUS_INCLUDE_DIR}
            IMPORTED_LOCATION ${LOG4CPLUS_LIBRARY_PATH})
    endif()
endif()
