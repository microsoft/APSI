# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate Microsoft GSL
set(CURRENT_MSGSL_INCLUDE_DIR ${MSGSL_INCLUDE_DIR})
unset(MSGSL_INCLUDE_DIR CACHE)
find_path(MSGSL_INCLUDE_DIR
    NAMES gsl/gsl gsl/span gsl/multi_span
    HINTS ${CURRENT_MSGSL_INCLUDE_DIR} ${CMAKE_INCLUDE_PATH})

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(msgsl
    REQUIRED_VARS MSGSL_INCLUDE_DIR)

if(msgsl_FOUND)
    # Create interface target for msgsl
    add_library(msgsl INTERFACE)

    set_target_properties(msgsl PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})
endif()
