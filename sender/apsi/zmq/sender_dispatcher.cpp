// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <thread>

// APSI
#include "apsi/log.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/requests.h"
#include "apsi/zmq/sender_dispatcher.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    using namespace network;
    using namespace oprf;
    using namespace util;

    namespace sender {
        ZMQSenderDispatcher::ZMQSenderDispatcher(shared_ptr<SenderDB> sender_db, OPRFKey oprf_key)
            : sender_db_(std::move(sender_db)), oprf_key_(std::move(oprf_key))
        {
            if (!sender_db_) {
                throw invalid_argument("sender_db is not set");
            }

            // If SenderDB is not stripped, the OPRF key it holds must be equal to the provided
            // oprf_key
            if (!sender_db_->is_stripped() && oprf_key_ != sender_db_->get_oprf_key()) {
                APSI_LOG_ERROR(
                    "Failed to create ZMQSenderDispatcher: SenderDB OPRF key differs "
                    "from the given OPRF key");
                throw logic_error("mismatching OPRF keys");
            }
        }

        ZMQSenderDispatcher::ZMQSenderDispatcher(shared_ptr<SenderDB> sender_db)
            : sender_db_(std::move(sender_db))
        {
            if (!sender_db_) {
                throw invalid_argument("sender_db is not set");
            }

            try {
                oprf_key_ = sender_db_->get_oprf_key();
            } catch (const logic_error &) {
                APSI_LOG_ERROR("Failed to create ZMQSenderDispatcher: missing OPRF key");
                throw;
            }
        }

        void ZMQSenderDispatcher::run(const atomic<bool> &stop, int port)
        {
            ZMQSenderChannel chl;

            stringstream ss;
            ss << "tcp://*:" << port;

            APSI_LOG_INFO("ZMQSenderDispatcher listening on port " << port);
            chl.bind(ss.str());

            auto seal_context = sender_db_->get_seal_context();

            // Checked once, here, rather than left to the serving loop. The loop treats a rise
            // in the channel's failure count as proof that a message was consumed and rejected,
            // and skips its back-off on that basis. An unusable SEALContext is the one condition
            // the channel reports as a failure without ever reading the socket, so leaving it to
            // be discovered per-iteration would turn the loop into a spin. It is also not a
            // condition that can improve by waiting: a SenderDB whose context is unusable can
            // never serve a query, so this is a startup error.
            if (!seal_context || !seal_context->parameters_set()) {
                throw runtime_error("SenderDB is not initialized with a valid SEALContext");
            }

            // Run until stopped
            bool logged_waiting = false;
            while (!stop) {
                // One peer must not be able to end the process. A malformed request is already
                // dropped by the channel, but everything downstream of that -- socket errors
                // from the send side, a failure deep inside query processing -- can still throw.
                // Contain it here and keep serving: dropping one exchange is the correct blast
                // radius for a server that handles requests from anyone.
                try {
                    uint64_t failures_before = chl.receive_failure_count();
                    unique_ptr<ZMQSenderOperation> sop =
                        chl.receive_network_operation(seal_context);
                    if (!sop) {
                        // Nothing to serve, but for one of two very different reasons. If the
                        // channel consumed a message and rejected it there is every chance more
                        // are waiting, and backing off would let a peer sending rubbish decide
                        // how fast this loop may take requests from everyone else. Only a
                        // genuinely empty poll is worth sleeping on.
                        if (chl.receive_failure_count() != failures_before) {
                            continue;
                        }

                        if (!logged_waiting) {
                            // We want to log 'Waiting' only once, even if we have to wait
                            // for several sleeps. And only once after processing a request as
                            // well.
                            logged_waiting = true;
                            APSI_LOG_INFO("Waiting for request from Receiver");
                        }

                        this_thread::sleep_for(50ms);
                        continue;
                    }

                    switch (sop->sop->type()) {
                    case SenderOperationType::sop_parms:
                        APSI_LOG_INFO("Received parameter request");
                        dispatch_parms(std::move(sop), chl);
                        break;

                    case SenderOperationType::sop_oprf:
                        APSI_LOG_INFO("Received OPRF request");
                        dispatch_oprf(std::move(sop), chl);
                        break;

                    case SenderOperationType::sop_query:
                        APSI_LOG_INFO("Received query");
                        dispatch_query(std::move(sop), chl);
                        break;

                    default:
                        APSI_LOG_ERROR(
                            "Received an operation of unhandled type "
                            << sender_operation_type_str(sop->sop->type()) << "; ignoring it");
                        break;
                    }
                } catch (const exception &ex) {
                    APSI_LOG_ERROR(
                        "Failed to handle a request from a Receiver: " << ex.what()
                                                                       << "; continuing");
                    // Back off before trying again. Whatever threw is likely to be there on the
                    // next iteration too, and a loop that logs and retries at full speed turns a
                    // persistent fault into a busy spin.
                    this_thread::sleep_for(50ms);
                } catch (...) {
                    // Nothing may escape this loop. An exception that does not derive from
                    // std::exception would otherwise leave run() and terminate a process that is
                    // still perfectly able to serve.
                    APSI_LOG_ERROR(
                        "Failed to handle a request from a Receiver with an unrecognized error; "
                        "continuing");
                    this_thread::sleep_for(50ms);
                }

                logged_waiting = false;
            }
        }

        void ZMQSenderDispatcher::dispatch_parms(
            unique_ptr<ZMQSenderOperation> sop, ZMQSenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "ZMQSenderDispatcher::dispatch_params");

            try {
                // Extract the parameter request
                ParamsRequest params_request = to_params_request(std::move(sop->sop));

                Sender::RunParams(
                    params_request,
                    sender_db_,
                    chl,
                    [&sop](Channel &c, unique_ptr<SenderOperationResponse> sop_response) {
                        auto nsop_response = make_unique<ZMQSenderOperationResponse>();
                        nsop_response->sop_response = std::move(sop_response);
                        nsop_response->client_id = std::move(sop->client_id);

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<ZMQSenderChannel &>(c).send(std::move(nsop_response));
                    });
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Sender threw an exception while processing parameter request: " << ex.what());
            }
        }

        void ZMQSenderDispatcher::dispatch_oprf(
            unique_ptr<ZMQSenderOperation> sop, ZMQSenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "ZMQSenderDispatcher::dispatch_oprf");

            try {
                // Extract the OPRF request
                OPRFRequest oprf_request = to_oprf_request(std::move(sop->sop));

                Sender::RunOPRF(
                    oprf_request,
                    oprf_key_,
                    chl,
                    [&sop](Channel &c, unique_ptr<SenderOperationResponse> sop_response) {
                        auto nsop_response = make_unique<ZMQSenderOperationResponse>();
                        nsop_response->sop_response = std::move(sop_response);
                        nsop_response->client_id = std::move(sop->client_id);

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<ZMQSenderChannel &>(c).send(std::move(nsop_response));
                    });
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Sender threw an exception while processing OPRF request: " << ex.what());
            }
        }

        void ZMQSenderDispatcher::dispatch_query(
            unique_ptr<ZMQSenderOperation> sop, ZMQSenderChannel &chl)
        {
            STOPWATCH(sender_stopwatch, "ZMQSenderDispatcher::dispatch_query");

            try {
                // Create the Query object
                Query query(to_query_request(std::move(sop->sop)), sender_db_);

                // Query will send result to client in a stream of ResultPackages (ResultParts)
                Sender::RunQuery(
                    query,
                    chl,
                    // Lambda function for sending the query response
                    [&sop](Channel &c, Response response) {
                        auto nsop_response = make_unique<ZMQSenderOperationResponse>();
                        nsop_response->sop_response = std::move(response);
                        nsop_response->client_id = sop->client_id;

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<ZMQSenderChannel &>(c).send(std::move(nsop_response));
                    },
                    // Lambda function for sending the result parts
                    [&sop](Channel &c, ResultPart rp) {
                        auto nrp = make_unique<ZMQResultPackage>();
                        nrp->rp = std::move(rp);
                        nrp->client_id = sop->client_id;

                        // We know for sure that the channel is a SenderChannel so use static_cast
                        static_cast<ZMQSenderChannel &>(c).send(std::move(nrp));
                    });
            } catch (const exception &ex) {
                APSI_LOG_ERROR("Sender threw an exception while processing query: " << ex.what());
            }
        }
    } // namespace sender
} // namespace apsi
