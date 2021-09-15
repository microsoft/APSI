// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

// APSI
#include "apsi/network/channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/query.h"
#include "apsi/requests.h"
#include "apsi/responses.h"
#include "apsi/sender_db.h"

namespace apsi {
    namespace sender {
        // An alias to denote the powers of a receiver's ciphertext. At index i, holds Cⁱ, where C
        // is the ciphertext. The 0th index is always a dummy value.
        using CiphertextPowers = std::vector<seal::Ciphertext>;

        /**
        The Sender class implements all necessary functions to process and respond to parameter,
        OPRF, and PSI or labeled PSI queries (depending on the sender). Unlike the Receiver class,
        Sender also takes care of actually sending data back to the receiver. Sender is a static
        class and cannot be instantiated.

        Like the Receiver, there are two ways of using the Sender. The "simple" approach supports
        network::ZMQChannel and is implemented in the ZMQSenderDispatcher class in
        zmq/sender_dispatcher.h. The ZMQSenderDispatcher provides a very fast way of deploying an
        APSI Sender: it automatically binds to a ZeroMQ socket, starts listening to requests, and
        acts on them as appropriate.

        The advanced Sender API consisting of three functions: RunParams, RunOPRF, and RunQuery. Of
        these, RunParams and RunOPRF take the request object (ParamsRequest or OPRFRequest) as
        input. RunQuery requires the QueryRequest to be "unpacked" into a Query object first.

        The full process for the sender is as follows:

        (1) Create a PSIParams object that is appropriate for the kinds of queries the sender is
        expecting to serve. Create a SenderDB object from the PSIParams. The SenderDB constructor
        optionally accepts an existing oprf::OPRFKey object and samples a random one otherwise. It
        is recommended to construct the SenderDB directly into a std::shared_ptr, as the Query
        constructor (see below) expects it to be passed as a std::shared_ptr<SenderDB>.

        (2) The sender's data must be loaded into the SenderDB with SenderDB::set_data. More data
        can always be added later with SenderDB::insert_or_assign, or removed with SenderDB::remove,
        as long as the SenderDB has not been stripped (see SenderDB::strip).

        (3 -- optional) Receive a parameter request with network::Channel::receive_operation. The
        received Request object must be converted to the right type (ParamsRequest) with the
        to_params_request function. This function will return nullptr if the received request was
        not of the right type. Once the request has been obtained, the RunParams function can be
        called with the ParamsRequest, the SenderDB, the network::Channel, and optionally a lambda
        function that implements custom logic for sending the ParamsResponse object on the channel.

        (4) Receive an OPRF request with network::Channel::receive_operation. The received Request
        object must be converted to the right type (OPRFRequest) with the to_oprf_request function.
        This function will return nullptr if the received request was not of the right type. Once
        the request has been obtained, the RunOPRF function can be called with the OPRFRequest, the
        oprf::OPRFKey, the network::Channel, and optionally a lambda function that implements custom
        logic for sending the OPRFResponse object on the channel.

        (5) Receive a query request with network::Channel::receive_operation. The received Request
        object must be converted to the right type (QueryRequest) with the to_query_request
        function. This function will return nullptr if the received request was not of the correct
        type. Once the request has been obtained, a Query object must be created from it. The
        constructor of the Query class verifies that the QueryRequest is valid for the given
        SenderDB, and if it is not the constructor still returns successfully but the Query is
        marked as invalid (Query::is_valid() returns false) and cannot be used in the next step.
        Once a valid Query object is created, the RunQuery function can be used to perform the query
        and respond on the given channel. Optionally, two lambda functions can be given to RunQuery
        to provide custom logic for sending the QueryResponse and the ResultPart objects on the
        channel.
        */
        class Sender {
        private:
            /**
            The most basic kind of function for sending an APSI message on a given channel. This
            function can be used unless the channel requires encapsulating the raw APSI messages,
            e.g., for including routing information or a digital signature. For example,
            network::ZMQChannel cannot use BasicSend; see zmq/sender_dispatcher.cpp for another
            example of a send function that works with the ZMQChannel.
            */
            template <typename T>
            static void BasicSend(network::Channel &chl, std::unique_ptr<T> pkg)
            {
                chl.send(std::move(pkg));
            }

        public:
            Sender() = delete;

            /**
            Generate and send a response to a parameter request.
            */
            static void RunParams(
                const ParamsRequest &params_request,
                std::shared_ptr<SenderDB> sender_db,
                network::Channel &chl,
                std::function<void(network::Channel &, Response)> send_fun =
                    BasicSend<Response::element_type>);

            /**
            Generate and send a response to an OPRF request.
            */
            static void RunOPRF(
                const OPRFRequest &oprf_request,
                oprf::OPRFKey key,
                network::Channel &chl,
                std::function<void(network::Channel &, Response)> send_fun =
                    BasicSend<Response::element_type>);

            /**
            Generate and send a response to a query.
            */
            static void RunQuery(
                const Query &query,
                network::Channel &chl,
                std::function<void(network::Channel &, Response)> send_fun =
                    BasicSend<Response::element_type>,
                std::function<void(network::Channel &, ResultPart)> send_rp_fun =
                    BasicSend<ResultPart::element_type>);

        private:
            /**
            Method that handles computing powers for a given bundle index
            */
            static void ComputePowers(
                const std::shared_ptr<SenderDB> &sender_db,
                const CryptoContext &crypto_context,
                std::vector<std::vector<seal::Ciphertext>> &powers,
                const PowersDag &pd,
                std::uint32_t bundle_idx,
                seal::MemoryPoolHandle &pool);

            /**
            Method that processes a single Bin Bundle cache.
            Sends a result package through the given channel.
            */
            static void ProcessBinBundleCache(
                const std::shared_ptr<SenderDB> &sender_db,
                const CryptoContext &crypto_context,
                std::reference_wrapper<const BinBundleCache> cache,
                std::vector<CiphertextPowers> &all_powers,
                network::Channel &chl,
                std::function<void(network::Channel &, ResultPart)> send_rp_fun,
                std::uint32_t bundle_idx,
                seal::compr_mode_type compr_mode,
                seal::MemoryPoolHandle &pool);
        }; // class Sender
    }      // namespace sender
} // namespace apsi
