# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

include(CheckCXXCompilerFlag)

# For easier adding of CXX compiler flags
function(apsi_enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

if(NOT MSVC AND APSI_DEBUG)
    apsi_enable_cxx_compiler_flag_if_supported("-Wall")
    apsi_enable_cxx_compiler_flag_if_supported("-Wextra")
    apsi_enable_cxx_compiler_flag_if_supported("-Wconversion")
    apsi_enable_cxx_compiler_flag_if_supported("-Wshadow")
    apsi_enable_cxx_compiler_flag_if_supported("-pedantic")
endif()
