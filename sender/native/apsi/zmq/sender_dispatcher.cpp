// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <cstddef>
#include <thread>

// APSI
#include "apsi/zmq/sender_dispatcher.h"
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
        SenderDispatcher::SenderDispatcher(shared_ptr<SenderDB> sender_db, size_t thread_count) :
            sender_db_(std::move(sender_db))
        {
            if (!sender_db_)
            {
                throw invalid_argument("sender_db is not set");
            }
            thread_count_ = thread_count < 1 ? thread::hardware_concurrency() : thread_count;
        }

        void SenderDispatcher::run(
            const atomic<bool> &stop, int port, shared_ptr<const OPRFKey> oprf_key)
        {
            SenderChannel chl;

            stringstream ss;
            ss << "tcp://*:" << port;

            APSI_LOG_INFO("SenderDispatcher listening on port " << port);
            chl.bind(ss.str());

            oprf_key_ = move(oprf_key);

            auto seal_context = sender_db_->get_context().seal_context();

            // Run until stopped
            bool logged_waiting = false;
            while (!stop)
            {
                unique_ptr<NetworkSenderOperation> sop;
                if (!(sop = chl.receive_network_operation(seal_context)))
                {
                    if (!logged_waiting)
                    {
                        // We want to log 'Waiting' only once, even if we have to wait
                        // for several sleeps. And only once after processing a request as well.
                        logged_waiting = true;
                        APSI_LOG_INFO("Waiting for request from Receiver");
                    }

                    this_thread::sleep_for(50ms);
                    continue;
                }

                switch (sop->sop->type())
                {
                case SenderOperationType::SOP_PARMS:
                    APSI_LOG_INFO("Received parameter request");
                    dispatch_parms(move(sop), chl);
                    break;

                case SenderOperationType::SOP_OPRF:
                    APSI_LOG_INFO("Received OPRF query");
                    dispatch_oprf(move(sop), chl);
                    break;

                case SenderOperationType::SOP_QUERY:
                    {
                        APSI_LOG_INFO("Received query");
                        dispatch_query(move(sop), chl);
                        break;
                    }

                default:
                    // We should never reach this point
                    throw runtime_error("invalid operation");
                }

                logged_waiting = false;
            }
        }

        void SenderDispatcher::dispatch_parms(unique_ptr<NetworkSenderOperation> sop, SenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "SenderDispatcher::dispatch_params");
            
            try
            {
                // Extract the parameter request
                ParmsRequest parms_request(move(sop->sop));

                Sender::RunParms(move(parms_request), sender_db_, chl,
                    [&sop](Channel &c, unique_ptr<SenderOperationResponse> sop_response) {
                        auto nsop_response = make_unique<NetworkSenderOperationResponse>();
                        nsop_response->sop_response = move(sop_response);
                        nsop_response->client_id = move(sop->client_id);

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<SenderChannel&>(c).send(move(nsop_response));
                    });
            }
            catch (const exception &e)
            {
                APSI_LOG_ERROR("APSI threw an exception while processing parameter request: " << e.what());
            }
        }

        void SenderDispatcher::dispatch_oprf(unique_ptr<NetworkSenderOperation> sop, SenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "SenderDispatcher::dispatch_oprf");

            try
            {
                // Extract the OPRF request
                OPRFRequest oprf_request(move(sop->sop));

                Sender::RunOPRF(move(oprf_request), *oprf_key_, chl,
                    [&sop](Channel &c, unique_ptr<SenderOperationResponse> sop_response) {
                        auto nsop_response = make_unique<NetworkSenderOperationResponse>();
                        nsop_response->sop_response = move(sop_response);
                        nsop_response->client_id = move(sop->client_id);

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<SenderChannel&>(c).send(move(nsop_response));
                    });
            }
            catch (const exception &e)
            {
                APSI_LOG_ERROR("APSI threw an exception while processing OPRF query: " << e.what());
            }
        }

        void SenderDispatcher::dispatch_query(unique_ptr<NetworkSenderOperation> sop, SenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "SenderDispatcher::dispatch_query");

            try
            {
                // Create the QueryRequest object
                QueryRequest query_request(move(sop->sop), sender_db_);

                // Query will send result to client in a stream of ResultPackages
                Sender::RunQuery(move(query_request), chl, thread_count_,
                    // Lambda function for sending the query response
                    [&sop](Channel &c, unique_ptr<SenderOperationResponse> sop_response) {
                        auto nsop_response = make_unique<NetworkSenderOperationResponse>();
                        nsop_response->sop_response = move(sop_response);
                        nsop_response->client_id = sop->client_id;

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<SenderChannel&>(c).send(move(nsop_response));
                    },
                    // Lambda function for sending the ResultPackages
                    [&sop](Channel &c, unique_ptr<ResultPackage> rp) {
                        auto nrp = make_unique<NetworkResultPackage>();
                        nrp->rp = move(rp);
                        nrp->client_id = sop->client_id;

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<SenderChannel&>(c).send(move(nrp));
                    });
            }
            catch (const exception &e)
            {
                APSI_LOG_ERROR("APSI threw an exception while processing query: " << e.what());
            }
        }
    } // namespace sender
} // namespace apsi
