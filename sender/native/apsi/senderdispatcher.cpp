// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <memory>

// APSI
#include "apsi/senderdispatcher.h"
#include "apsi/network/senderchannel.h"
#include "apsi/network/network_utils.h"
#include "apsi/logging/log.h"
#include "apsi/oprf/oprf_sender.h"

// SEAL
#include "seal/publickey.h"
#include "seal/relinkeys.h"


using namespace std;
using namespace seal;

namespace apsi
{
    using namespace network;
    using namespace logging;
    using namespace oprf;

    namespace sender
    {
        void SenderDispatcher::run(
            const atomic<bool> &stop,
            int port,
            shared_ptr<const OPRFKey> oprf_key,
            shared_ptr<SenderDB> sender_db)
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
                shared_ptr<SenderOperation> sender_op;

                if (!channel.receive(sender_op))
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

                switch (sender_op->type)
                {
                case SOP_get_parameters:
                    Log::info("Received Get Parameters request");
                    dispatch_get_parameters(sender_op, channel);
                    break;

                case SOP_preprocess:
                    Log::info("Received Preprocess request");
                    dispatch_preprocess(sender_op, channel);
                    break;

                case SOP_query:
                    Log::info("Received Query request");
                    dispatch_query(sender_op, channel);
                    break;

                default:
                    Log::error("Invalid Sender Operation: %i", sender_op->type);
                }

                logged_waiting = false;
            }
        }

        void SenderDispatcher::dispatch_get_parameters(shared_ptr<SenderOperation> sender_op, Channel& channel)
        {
            // No need to cast to SenderOperationGetParameters, we just need the client_id.
            channel.send_get_parameters_response(sender_op->client_id, sender_->get_params());
        }

        void SenderDispatcher::dispatch_preprocess(shared_ptr<SenderOperation> sender_op, Channel& channel)
        {
            auto preprocess_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
            
            vector<SEAL_BYTE> result(preprocess_op->buffer.size());
            OPRFSender::ProcessQueries(preprocess_op->buffer, *oprf_key_, result);
            channel.send_preprocess_response(sender_op->client_id, result);
        }

        void SenderDispatcher::dispatch_query(shared_ptr<SenderOperation> sender_op, Channel& channel)
        {
            auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);

            // The query response will tell the Receiver how many ResultPackages to expect
            size_t package_count = sender_->get_params().batch_count() * sender_->get_params().split_count();
            channel.send_query_response(sender_op->client_id, package_count);

            // Query will send result to client in a stream of ResultPackages
            sender_->query(
                query_op->relin_keys,
                query_op->query,
                sender_op->client_id,
                channel);
        }
    } // namespace sender
} // namespace apsi