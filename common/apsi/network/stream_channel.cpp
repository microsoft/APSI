// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <stdexcept>
#include <utility>

// APSI
#include "apsi/log.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/stream_channel.h"

using namespace std;
using namespace seal;

namespace apsi::network {
    namespace {
        /**
        Hands a message to the stream's sink and reports one that could not take it. Both halves
        are necessary. The save functions return the number of bytes they meant to write rather
        than the number that arrived, and a failed ostream swallows a write without complaint,
        so the stream has to be asked. Asking is only meaningful once the bytes have been
        offered to the sink: a buffered stream holds a whole message without consulting its sink
        at all, and a sender writes a fixed number of result packages and then stops, so a
        failure on the last of them would otherwise never be observed by anything.
        */
        void flush_or_throw(ostream &out, const char *what)
        {
            out.flush();
            if (!out) {
                APSI_LOG_ERROR("Failed to send " << what << ": the stream would not take it");
                throw runtime_error(
                    string("failed to send ") + what + ": the stream would not take it");
            }
        }
    } // namespace

    void StreamChannel::send(unique_ptr<SenderOperation> sop)
    {
        // Need to have the SenderOperation package
        if (!sop) {
            APSI_LOG_ERROR("Failed to send operation: operation data is missing");
            throw invalid_argument("operation data is missing");
        }

        // Construct the header
        SenderOperationHeader sop_header;
        sop_header.type = sop->type();
        APSI_LOG_DEBUG("Sending operation of type " << sender_operation_type_str(sop_header.type));

        lock_guard<mutex> lock(send_mutex_);
        size_t old_bytes_sent = bytes_sent_;

        // Counted only once the stream has taken them, so that bytes_sent reports what was sent
        // rather than what was attempted.
        size_t bytes = sop_header.save(out_);
        bytes += sop->save(out_);
        flush_or_throw(out_, "an operation");
        bytes_sent_ += bytes;

        APSI_LOG_DEBUG(
            "Sent an operation of type " << sender_operation_type_str(sop_header.type) << " ("
                                         << bytes_sent_ - old_bytes_sent << " bytes)");
    }

    unique_ptr<SenderOperation> StreamChannel::receive_operation(
        shared_ptr<SEALContext> context, SenderOperationType expected)
    {
        bool valid_context = context && context->parameters_set();
        if (!valid_context && (expected == SenderOperationType::sop_unknown ||
                               expected == SenderOperationType::sop_query)) {
            // Cannot receive unknown or query operations without a valid SEALContext
            APSI_LOG_ERROR(
                "Cannot receive an operation of type " << sender_operation_type_str(expected)
                                                       << "; SEALContext is missing or invalid");
            set_receive_failed();
            return nullptr;
        }

        lock_guard<mutex> lock(receive_mutex_);
        size_t old_bytes_received = bytes_received_;

        SenderOperationHeader sop_header;
        try {
            bytes_received_ += sop_header.load(in_);
        } catch (const runtime_error &) {
            // Invalid header
            APSI_LOG_ERROR("Failed to receive a valid header");
            set_receive_failed();
            return nullptr;
        } catch (const exception &ex) {
            // Any other failure, e.g. allocation failure from an oversized size prefix
            APSI_LOG_ERROR("Failed to receive a valid header: " << ex.what());
            set_receive_failed();
            return nullptr;
        }

        if (!same_serialization_version(sop_header.version)) {
            // Check that the serialization version numbers match
            APSI_LOG_ERROR(
                "Received header indicates a serialization version number ("
                << sop_header.version
                << ") incompatible with the current serialization version number ("
                << apsi_serialization_version << ")");
            set_receive_failed();
            return nullptr;
        }

        if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
            // Unexpected operation
            APSI_LOG_ERROR(
                "Received header indicates an unexpected operation type "
                << sender_operation_type_str(sop_header.type));
            set_receive_failed();
            return nullptr;
        }

        // Return value
        unique_ptr<SenderOperation> sop = nullptr;

        try {
            switch (sop_header.type) {
            case SenderOperationType::sop_parms:
                sop = make_unique<SenderOperationParms>();
                bytes_received_ += sop->load(in_);
                break;
            case SenderOperationType::sop_oprf:
                sop = make_unique<SenderOperationOPRF>();
                bytes_received_ += sop->load(in_);
                break;
            case SenderOperationType::sop_query:
                sop = make_unique<SenderOperationQuery>();
                bytes_received_ += sop->load(in_, std::move(context));
                break;
            default:
                // Invalid operation
                APSI_LOG_ERROR(
                    "Received header indicates an invalid operation type "
                    << sender_operation_type_str(sop_header.type));
                set_receive_failed();
                return nullptr;
            }
        } catch (const invalid_argument &ex) {
            APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
            set_receive_failed();
            return nullptr;
        } catch (const runtime_error &ex) {
            APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
            set_receive_failed();
            return nullptr;
        } catch (const exception &ex) {
            // Any other failure, e.g. allocation failure from an oversized size prefix
            APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
            set_receive_failed();
            return nullptr;
        }

        // Loaded successfully
        APSI_LOG_DEBUG(
            "Received an operation of type " << sender_operation_type_str(sop_header.type) << " ("
                                             << bytes_received_ - old_bytes_received << " bytes)");

        return sop;
    }

    void StreamChannel::send(unique_ptr<SenderOperationResponse> sop_response)
    {
        // Need to have the SenderOperationResponse package
        if (!sop_response) {
            APSI_LOG_ERROR("Failed to send response: response data is missing");
            throw invalid_argument("response data is missing");
        }

        // Construct the header
        SenderOperationHeader sop_header;
        sop_header.type = sop_response->type();
        APSI_LOG_DEBUG("Sending response of type " << sender_operation_type_str(sop_header.type));

        lock_guard<mutex> lock(send_mutex_);
        size_t old_bytes_sent = bytes_sent_;

        size_t bytes = sop_header.save(out_);
        bytes += sop_response->save(out_);
        flush_or_throw(out_, "a response");
        bytes_sent_ += bytes;

        APSI_LOG_DEBUG(
            "Sent a response of type " << sender_operation_type_str(sop_header.type) << " ("
                                       << bytes_sent_ - old_bytes_sent << " bytes)");
    }

    unique_ptr<SenderOperationResponse> StreamChannel::receive_response(
        SenderOperationType expected)
    {
        lock_guard<mutex> lock(receive_mutex_);
        size_t old_bytes_received = bytes_received_;

        SenderOperationHeader sop_header;
        try {
            bytes_received_ += sop_header.load(in_);
        } catch (const runtime_error &) {
            // Invalid header
            APSI_LOG_ERROR("Failed to receive a valid header");
            set_receive_failed();
            return nullptr;
        } catch (const exception &ex) {
            // Any other failure, e.g. allocation failure from an oversized size prefix
            APSI_LOG_ERROR("Failed to receive a valid header: " << ex.what());
            set_receive_failed();
            return nullptr;
        }

        if (!same_serialization_version(sop_header.version)) {
            // Check that the serialization version numbers match
            APSI_LOG_ERROR(
                "Received header indicates a serialization version number "
                << sop_header.version
                << " incompatible with the current serialization version number "
                << apsi_serialization_version);
            set_receive_failed();
            return nullptr;
        }

        if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
            // Unexpected operation
            APSI_LOG_ERROR(
                "Received header indicates an unexpected operation type "
                << sender_operation_type_str(sop_header.type));
            set_receive_failed();
            return nullptr;
        }

        // Return value
        unique_ptr<SenderOperationResponse> sop_response = nullptr;

        try {
            switch (sop_header.type) {
            case SenderOperationType::sop_parms:
                sop_response = make_unique<SenderOperationResponseParms>();
                bytes_received_ += sop_response->load(in_);
                break;
            case SenderOperationType::sop_oprf:
                sop_response = make_unique<SenderOperationResponseOPRF>();
                bytes_received_ += sop_response->load(in_);
                break;
            case SenderOperationType::sop_query:
                sop_response = make_unique<SenderOperationResponseQuery>();
                bytes_received_ += sop_response->load(in_);
                break;
            default:
                // Invalid operation
                APSI_LOG_ERROR(
                    "Received header indicates an invalid operation type "
                    << sender_operation_type_str(sop_header.type));
                set_receive_failed();
                return nullptr;
            }
        } catch (const runtime_error &ex) {
            APSI_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
            set_receive_failed();
            return nullptr;
        } catch (const exception &ex) {
            // Any other failure, e.g. allocation failure from an oversized size prefix
            APSI_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
            set_receive_failed();
            return nullptr;
        }

        // Loaded successfully
        APSI_LOG_DEBUG(
            "Received a response of type " << sender_operation_type_str(sop_header.type) << " ("
                                           << bytes_received_ - old_bytes_received << " bytes)");

        return sop_response;
    }

    void StreamChannel::send(unique_ptr<ResultPackage> rp)
    {
        // Need to have the ResultPackage
        if (!rp) {
            APSI_LOG_ERROR("Failed to send result package: result package data is missing");
            throw invalid_argument("result package data is missing");
        }

        APSI_LOG_DEBUG(
            "Sending result package ("
            << "has matching data: " << (rp->psi_result ? "yes" : "no") << "; "
            << "label byte count: " << rp->label_byte_count << "; "
            << "nonce byte count: " << rp->nonce_byte_count << "; "
            << "has label data: " << (!rp->label_result.empty() ? "yes" : "no") << ")");

        lock_guard<mutex> lock(send_mutex_);
        size_t old_bytes_sent = bytes_sent_;

        size_t bytes = rp->save(out_);
        flush_or_throw(out_, "a result package");
        bytes_sent_ += bytes;

        APSI_LOG_DEBUG("Sent a result package (" << bytes_sent_ - old_bytes_sent << " bytes)");
    }

    unique_ptr<ResultPackage> StreamChannel::receive_result(shared_ptr<SEALContext> context)
    {
        bool valid_context = context && context->parameters_set();
        if (!valid_context) {
            // Cannot receive a result package without a valid SEALContext
            APSI_LOG_ERROR("Cannot receive a result package; SEALContext is missing or invalid");
            set_receive_failed();
            return nullptr;
        }

        lock_guard<mutex> lock(receive_mutex_);
        size_t old_bytes_received = bytes_received_;

        // Return value
        unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

        try {
            bytes_received_ += rp->load(in_, context);
        } catch (const invalid_argument &ex) {
            APSI_LOG_ERROR("An exception was thrown loading result package data: " << ex.what());
            set_receive_failed();
            return nullptr;
        } catch (const runtime_error &ex) {
            APSI_LOG_ERROR("An exception was thrown loading result package data: " << ex.what());
            set_receive_failed();
            return nullptr;
        } catch (const exception &ex) {
            // Any other failure, e.g. allocation failure from an oversized size prefix
            APSI_LOG_ERROR("An exception was thrown loading result package data: " << ex.what());
            set_receive_failed();
            return nullptr;
        }

        // Loaded successfully
        APSI_LOG_DEBUG(
            "Received a result package (" << bytes_received_ - old_bytes_received << " bytes)");

        return rp;
    }
} // namespace apsi::network
