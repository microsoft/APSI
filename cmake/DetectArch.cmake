# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET ON)
if(MSVC)
    check_cxx_source_runs("
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
    check_cxx_source_runs("
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
    check_cxx_source_runs("
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
    check_cxx_source_runs("
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
