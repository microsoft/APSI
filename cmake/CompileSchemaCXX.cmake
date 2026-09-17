# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# flatc runs here, at configure time, so a build alone will not regenerate a header after its
# schema changes: the stale header is compiled instead and fails on whatever the schema added.
# Listing the schemas as configure dependencies makes CMake re-run this step when one of them is
# edited, so that a plain build is enough.
set_property(
    DIRECTORY "${APSI_SOURCE_DIR}"
    APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${APSI_SOURCE_DIR}/common/apsi/network/ciphertext.fbs"
        "${APSI_SOURCE_DIR}/common/apsi/network/result_package.fbs"
        "${APSI_SOURCE_DIR}/common/apsi/network/sop.fbs"
        "${APSI_SOURCE_DIR}/common/apsi/network/sop_header.fbs"
        "${APSI_SOURCE_DIR}/common/apsi/network/sop_response.fbs"
        "${APSI_SOURCE_DIR}/common/apsi/psi_params.fbs"
        "${APSI_SOURCE_DIR}/sender/apsi/bin_bundle.fbs"
        "${APSI_SOURCE_DIR}/sender/apsi/sender_db.fbs"
        "${APSI_SOURCE_DIR}/sender/apsi/util/cuckoo_filter.fbs"
)

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_BUILD_DIR}/common/apsi" "${APSI_SOURCE_DIR}/common/apsi/psi_params.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_BUILD_DIR}/common/apsi/network" "${APSI_SOURCE_DIR}/common/apsi/network/ciphertext.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_BUILD_DIR}/common/apsi/network" "${APSI_SOURCE_DIR}/common/apsi/network/sop.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_BUILD_DIR}/common/apsi/network" "${APSI_SOURCE_DIR}/common/apsi/network/sop_header.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_BUILD_DIR}/common/apsi/network" "${APSI_SOURCE_DIR}/common/apsi/network/sop_response.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_BUILD_DIR}/common/apsi/network" "${APSI_SOURCE_DIR}/common/apsi/network/result_package.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/" -o "${APSI_BUILD_DIR}/sender/apsi" "${APSI_SOURCE_DIR}/sender/apsi/bin_bundle.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/" -I "${APSI_SOURCE_DIR}/common/apsi" -o "${APSI_BUILD_DIR}/sender/apsi" "${APSI_SOURCE_DIR}/sender/apsi/sender_db.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_BUILD_DIR}/sender/apsi/util" "${APSI_SOURCE_DIR}/sender/apsi/util/cuckoo_filter.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()
