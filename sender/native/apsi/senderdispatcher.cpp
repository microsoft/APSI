// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <cstddef>

// APSI
#include "apsi/senderdispatcher.h"
#include "apsi/network/senderchannel.h"
#include "apsi/logging/log.h"
#include "apsi/oprf/oprf_sender.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    using namespace network;
    using namespace logging;
    using namespace oprf;

    namespace sender
    {
        void SenderDispatcher::run(
            const atomic<bool> &stop, int port, shared_ptr<const OPRFKey> oprf_key, shared_ptr<SenderDB> sender_db)
        {
            SenderChannel channel;

            stringstream ss;
            ss << "tcp://*:" << port;

            Log::info("Sender binding to address: %s", ss.str().c_str());
            channel.bind(ss.str());

            oprf_key_ = move(oprf_key);
            sender_->set_db(move(sender_db));

            bool logged_waiting = false;

            // Run until stopped
            while (!stop)
            {
                unique_ptr<SenderOperation> sop;
                if (!(sop = channel.receive_operation()))
                {
                    if (!logged_waiting)
                    {
                        // We want to log 'Waiting' only once, even if we have to wait
                        // for several sleeps. And only once after processing a request as well.
                        logged_waiting = true;
                        Log::info("Waiting for request.");
                    }

                    this_thread::sleep_for(50ms);
                    continue;
                }

                switch (sop->type())
                {
                case SenderOperationType::SOP_PARMS:
                    Log::info("Received parameter request");
                    dispatch_parms(move(sop), channel);
                    break;

                case SenderOperationType::SOP_OPRF:
                    Log::info("Received OPRF query");
                    dispatch_oprf(move(sop), channel);
                    break;

                case SenderOperationType::SOP_QUERY:
                    Log::info("Received query");
                    dispatch_query(move(sop), channel);
                    break;

                default:
                    // We should never reach this point
                    throw runtime_error("invalid operation");
                }

                logged_waiting = false;
            }
        }

        void SenderDispatcher::dispatch_parms(unique_ptr<SenderOperation> sop, Channel &channel)
        {
            unique_ptr<SenderOperationResponse> response(make_unique<SenderOperationResponseParms>(
                sender_->get_params(), move(sop->client_id)));
            channel.send(move(response));
        }

        void SenderDispatcher::dispatch_oprf(unique_ptr<SenderOperationOPRF> sop, Channel &channel)
        {
            SenderOperationOPRF *sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop.get());

            // OPRF response it the same size as the OPRF query 
            vector<SEAL_BYTE> oprf_response(sop_oprf->data.size());
            OPRFSender::ProcessQueries(sop_oprf->data, *oprf_key_, oprf_response);

            unique_ptr<SenderOperationResponse> response(make_unique<SenderOperationResponseOPRF>(
                move(oprf_response), move(sop->client_id)));
            channel.send(move(response));
        }

        void SenderDispatcher::dispatch_query(unique_ptr<SenderOperation> sop, Channel &channel)
        {
            // Acquire read locks on SenderDB and Sender
            auto sender_db_lock = sender_db_->get_reader_lock();
            auto sender_lock = sender_->get_reader_lock();

            SenderOperationQuery *sop_query = dynamic_cast<SenderOperationQuery*>(sop.get());

            // The query response only tells how many ResultPackages to expect
            uint32_t package_count = safe_cast<uint32_t>(sender_db_->bin_bundle_count());

            unique_ptr<SenderOperationResponse> response(make_unique<SenderOperationResponseQuery>(
                package_count, sop->client_id));
            channel.send(move(response));

            // Query will send result to client in a stream of ResultPackages
            sender_->query(move(sop_query->relin_keys), move(sop_query->data), move(sop_query->client_id), channel);
        }
    } // namespace sender
} // namespace apsi
