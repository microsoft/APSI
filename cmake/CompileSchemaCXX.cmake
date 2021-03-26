# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi" "${APSI_SOURCE_DIR}/common/native/apsi/psi_params.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/ciphertext.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop_header.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/sop_response.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/network/" -o "${APSI_SOURCE_DIR}/common/native/apsi/network" "${APSI_SOURCE_DIR}/common/native/apsi/network/result_package.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/" -o "${APSI_SOURCE_DIR}/sender/native/apsi" "${APSI_SOURCE_DIR}/sender/native/apsi/bin_bundle.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()

execute_process(
    COMMAND ${FLATBUFFERS_FLATC_PATH} --cpp --include-prefix "apsi/" -I "${APSI_SOURCE_DIR}/common/native/apsi" -o "${APSI_SOURCE_DIR}/sender/native/apsi" "${APSI_SOURCE_DIR}/sender/native/apsi/sender_db.fbs"
    OUTPUT_QUIET
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "flatc failed (${result})")
endif()
