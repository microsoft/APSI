// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <utility>
#include <cstddef>
#include <stdexcept>

// APSI
#include "apsi/network/stream_channel.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/result_package_generated.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace network
    {
        void StreamChannel::send(unique_ptr<SenderOperation> sop)
        {
            // Need to have the SenderOperation package
            if (!sop)
            {
                throw invalid_argument("operation data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop->type();

            lock_guard<mutex> lock(send_mutex_);

            bytes_sent_ += sop_header.save(out_);
            bytes_sent_ += sop->save(out_);
        }

        unique_ptr<SenderOperation> StreamChannel::receive_operation(
            shared_ptr<SEALContext> context,
            SenderOperationType expected)
        {
            lock_guard<mutex> lock(receive_mutex_);

            bool valid_context = context && context->parameters_set();
            if (!valid_context && (expected == SenderOperationType::sop_unknown || expected == SenderOperationType::sop_query))
            {
                // Cannot receive unknown or query operations without a valid SEALContext
                return nullptr;
            }

            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += sop_header.load(in_);
            }
            catch (const runtime_error &ex)
            {
                // Invalid header
                return nullptr;
            }

            if (!same_version(sop_header.version))
            {
                // Check that the version numbers match exactly
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type)
            {
                // Unexpected operation
                return nullptr;
            }

            // Return value
            unique_ptr<SenderOperation> sop = nullptr;

            try
            {
                switch (static_cast<SenderOperationType>(sop_header.type))
                {
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
                        bytes_received_ += sop->load(in_, move(context));
                        break;
                    default:
                        // Invalid operation
                        return nullptr;
                }
            }
            catch (const invalid_argument &ex)
            {
                // Invalid SEALContext
                return nullptr;
            }
            catch (const runtime_error &ex)
            {
                // Invalid operation data
                return nullptr;
            }

            // Loaded successfully
            return sop;
        }

        void StreamChannel::send(unique_ptr<SenderOperationResponse> sop_response)
        {
            // Need to have the SenderOperationResponse package
            if (!sop_response)
            {
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop_response->type();

            lock_guard<mutex> lock(send_mutex_);

            bytes_sent_ += sop_header.save(out_);
            bytes_sent_ += sop_response->save(out_);
        }

        unique_ptr<SenderOperationResponse> StreamChannel::receive_response(SenderOperationType expected)
        {
            lock_guard<mutex> lock(receive_mutex_);

            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += sop_header.load(in_);
            }
            catch (const runtime_error &ex)
            {
                // Invalid header
                return nullptr;
            }

            if (!same_version(sop_header.version))
            {
                // Check that the version numbers match exactly
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type)
            {
                // Unexpected operation
                return nullptr;
            }

            // Return value
            unique_ptr<SenderOperationResponse> sop_response = nullptr;

            try
            {
                switch (static_cast<SenderOperationType>(sop_header.type))
                {
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
                        return nullptr;
                }
            }
            catch (const runtime_error &ex)
            {
                // Invalid response data
                return nullptr;
            }

            // Loaded successfully
            return sop_response;
        }

        void StreamChannel::send(unique_ptr<ResultPackage> rp)
        {
            lock_guard<mutex> lock(send_mutex_);

            bytes_sent_ += rp->save(out_);
        }

        unique_ptr<ResultPackage> StreamChannel::receive_result(shared_ptr<SEALContext> context)
        {
            lock_guard<mutex> lock(receive_mutex_);

            bool valid_context = context && context->parameters_set();
            if (!valid_context)
            {
                // Cannot receive a result package without a valid SEALContext
                return nullptr;
            }

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try
            {
                bytes_received_ += rp->load(in_, move(context));
            }
            catch (const invalid_argument &ex)
            {
                // Invalid SEALContext
                return nullptr;
            }
            catch (const runtime_error &ex)
            {
                // Invalid result package data
                return nullptr;
            }

            // Loaded successfully
            return rp;
        }
    } // namespace network
} // namespace apsi
