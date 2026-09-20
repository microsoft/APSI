# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# These probes are preprocessor tests: compiling one already establishes that the macro it
# guards is defined, so they must not require running the result. A cross-build produces a
# binary the host cannot execute, which would report every architecture as absent and leave
# FourQ with no target at all.
include(CheckCXXSourceCompiles)

set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET ON)
if(MSVC)
    check_cxx_source_compiles("
        #if defined(_M_ARM64)
            int main() {
                return 0;
            }
        #else
            #error
        #endif
        "
        APSI_FOURQ_ARM64
    )
    check_cxx_source_compiles("
        #if defined(_M_AMD64)
            int main() {
                return 0;
            }
        #else
            #error
        #endif
        "
        APSI_FOURQ_AMD64
    )
else()
    check_cxx_source_compiles("
        #if defined(__aarch64__)
            int main() {
                return 0;
            }
        #else
            #error
        #endif
        "
        APSI_FOURQ_ARM64
    )
    check_cxx_source_compiles("
        #if defined(__amd64)
            int main() {
                return 0;
            }
        #else
            #error
        #endif
        "
        APSI_FOURQ_AMD64
    )
endif()
set(CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_OLD})
