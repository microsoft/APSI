# Simple attempt to locate ZeroMQ
set(CURRENT_ZEROMQ_INCLUDE_DIR ${ZEROMQ_INCLUDE_DIR})
set(CURRENT_ZEROMQ_LIBRARY_DIR ${ZEROMQ_LIBRARY_DIR})
set(CURRENT_ZEROMQ_LIBRARY_PATH ${ZEROMQ_LIBRARY_PATH})

unset(ZEROMQ_INCLUDE_DIR CACHE)
find_path(ZEROMQ_INCLUDE_DIR
    NAMES zmq.h zmq_utils.h
    HINTS ${CMAKE_INCLUDE_DIR} ${CURRENT_ZEROMQ_INCLUDE_DIR})

unset(ZEROMQ_LIBRARY_DIR CACHE)
unset(ZEROMQ_LIBRARY_PATH CACHE)
find_library(ZEROMQ_LIBRARY_PATH
    NAMES zmq
    HINTS ${CMAKE_LIBRARY_PATH} ${CURRENT_ZEROMQ_LIBRARY_DIR})
if(ZEROMQ_LIBRARY_PATH)
    get_filename_component(ZEROMQ_LIBRARY_DIR ${ZEROMQ_LIBRARY_PATH} DIRECTORY CACHE)
endif()

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(ZeroMQ
    REQUIRED_VARS ZEROMQ_INCLUDE_DIR ZEROMQ_LIBRARY_DIR ZEROMQ_LIBRARY_PATH)

if(ZeroMQ_FOUND)
    # Create interface target for ZeroMQ
    add_library(ZeroMQ UNKNOWN IMPORTED)

    set_target_properties(ZeroMQ PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${ZEROMQ_INCLUDE_DIR}
        IMPORTED_LOCATION ${ZEROMQ_LIBRARY_PATH})
endif()
