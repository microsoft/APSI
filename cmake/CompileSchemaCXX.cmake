# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

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
