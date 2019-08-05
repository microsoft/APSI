# Exports target Cuckoo::Cuckoo
#
# Creates variables:
#   CUCKOO_BUILD_TYPE : The build configuration used
#   CUCKOO_DEBUG : Set to non-zero value if Cuckoo is compiled with extra debugging code

set(CUCKOO_BUILD_TYPE Release)
set(CUCKOO_DEBUG OFF)

include(${CMAKE_CURRENT_LIST_DIR}/CuckooTargets.cmake)
message(STATUS "Cuckoo detected (version ${CUCKOO_VERSION})")
message(STATUS "Cuckoo build type: ${CUCKOO_BUILD_TYPE}")
message(STATUS "Cuckoo debug mode: ${CUCKOO_DEBUG}")
