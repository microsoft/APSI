# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Vendored Microsoft FourQlib reference implementation. See README.md and cgmanifest.json
# for upstream + commit pinning. APSI's OPRF source includes FourQ headers via the
# "apsi/fourq/X.h" prefix, so we mirror the headers from this directory into
# ${CMAKE_BINARY_DIR}/common/apsi/fourq/ at configure time. The path
# ${CMAKE_BINARY_DIR}/common is on apsi's PUBLIC include path (set in the top-level
# CMakeLists.txt), so the existing #include paths resolve without source changes.

set(APSI_FOURQ_HEADERS
    FourQ.h
    FourQ_api.h
    FourQ_internal.h
    FourQ_params.h
    FourQ_tables.h
    random.h
    table_lookup.h
)

foreach(_h IN LISTS APSI_FOURQ_HEADERS)
    configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/${_h}
        ${CMAKE_BINARY_DIR}/common/apsi/fourq/${_h}
        COPYONLY)
endforeach()

# Source files in this directory
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/crypto_util.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_core.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_no_endo.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2.c
    ${CMAKE_CURRENT_LIST_DIR}/hash_to_curve.c
    ${CMAKE_CURRENT_LIST_DIR}/random.c
)

if(APSI_FOURQ_AMD64)
    add_subdirectory(amd64)
elseif(APSI_FOURQ_ARM64)
    add_subdirectory(arm64)
else()
    add_subdirectory(generic)
endif()
set(APSI_SOURCE_FILES ${APSI_SOURCE_FILES} PARENT_SCOPE)
