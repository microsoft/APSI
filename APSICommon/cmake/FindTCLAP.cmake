# Simple attempt to locate TCLAP
set(CURRENT_TCLAP_INCLUDE_DIR ${TCLAP_INCLUDE_DIR})
unset(TCLAP_INCLUDE_DIR CACHE)
find_path(TCLAP_INCLUDE_DIR
    NAMES tclap/CmdLine.h
    HINTS ${CMAKE_INCLUDE_PATH} ${CURRENT_TCLAP_INCLUDE_DIR})

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(TCLAP
    REQUIRED_VARS TCLAP_INCLUDE_DIR)

if(TCLAP_FOUND)
    # Create interface target for TCLAP
    add_library(TCLAP INTERFACE)
    set_target_properties(TCLAP PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${TCLAP_INCLUDE_DIR})
endif()
