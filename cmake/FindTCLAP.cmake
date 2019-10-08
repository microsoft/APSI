# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(TCLAP_INCLUDE_DIR NAMES tclap/CmdLine.h)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(TCLAP
    REQUIRED_VARS TCLAP_INCLUDE_DIR)

if(TCLAP_FOUND AND NOT TARGET TCLAP::TCLAP)
    # Create interface target for TCLAP 
    add_library(TCLAP::TCLAP IMPORTED INTERFACE)
    set_target_properties(TCLAP::TCLAP PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${TCLAP_INCLUDE_DIR})
endif()
