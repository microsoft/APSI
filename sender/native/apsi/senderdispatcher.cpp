// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <cstddef>

// APSI
#include "apsi/senderdispatcher.h"
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
            const atomic<bool> &stop, int port, shared_ptr<const OPRFKey> oprf_key)
        {
            SenderChannel chl;

            stringstream ss;
            ss << "tcp://*:" << port;

            APSI_LOG_INFO("Sender binding to address: " << ss.str());
            chl.bind(ss.str());

            oprf_key_ = move(oprf_key);

            // Setting up the Sender object
            Sender sender(sender_db_->get_params(), thread_count_);

            bool logged_waiting = false;

            // Run until stopped
            while (!stop)
            {
                unique_ptr<NetworkSenderOperation> sop;
                if (!(sop = chl.receive_network_operation(sender.get_seal_context())))
                {
                    if (!logged_waiting)
                    {
                        // We want to log 'Waiting' only once, even if we have to wait
                        // for several sleeps. And only once after processing a request as well.
                        logged_waiting = true;
                        APSI_LOG_INFO("Waiting for request.");
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
                        dispatch_query(sender, move(sop), chl);
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
            auto response_parms = make_unique<SenderOperationResponseParms>();
            response_parms->params = make_unique<PSIParams>(sender_db_->get_params());
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_parms);
            response->client_id = move(sop->client_id);

            chl.send(move(response));
        }

        void SenderDispatcher::dispatch_oprf(unique_ptr<NetworkSenderOperation> sop, SenderChannel &chl)
        {
            auto sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop->sop.get());

            // OPRF response has the same size as the OPRF query 
            vector<SEAL_BYTE> oprf_response(sop_oprf->data.size());
            OPRFSender::ProcessQueries(sop_oprf->data, *oprf_key_, oprf_response);

            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = move(oprf_response);
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_oprf);
            response->client_id = move(sop->client_id);

            chl.send(move(response));
        }

        void SenderDispatcher::dispatch_query(
            const Sender &sender,
            unique_ptr<NetworkSenderOperation> sop,
            SenderChannel &chl)
        {
            // Acquire read lock on SenderDB
            auto sender_db_lock = sender_db_->get_reader_lock();

            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop->sop.get());

            // The query response only tells how many ResultPackages to expect
            uint32_t package_count = safe_cast<uint32_t>(sender_db_->bin_bundle_count());

            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_query);
            response->client_id = sop->client_id;

            chl.send(move(response));

            // Query will send result to client in a stream of ResultPackages
            sender.query(sop_query->relin_keys.extract_local(), move(sop_query->data), chl,
                [&response](Channel &c, unique_ptr<ResultPackage> rp) {
                    auto nrp = make_unique<NetworkResultPackage>();
                    nrp->rp = move(rp);
                    nrp->client_id = move(response->client_id);

                    // We know for sure that the channel is a SenderChannel so use static_cast
                    static_cast<SenderChannel&>(c).send(move(nrp));
                });
        }
    } // namespace sender
} // namespace apsi
