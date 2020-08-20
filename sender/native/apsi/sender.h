// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <unordered_map>
#include <memory>
#include <utility>
#include <vector>

// APSI
#include "apsi/cryptocontext.h"
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psiparams.h"
#include "apsi/sealobject.h"
#include "apsi/senderdb.h"

// SEAL
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"
#include "seal/util/defines.h"

namespace apsi
{
    namespace sender
    {
        class ParmsRequest
        {
        friend class Sender;

        public:
            ParmsRequest(std::unique_ptr<network::SenderOperation> sop);

            ParmsRequest deep_copy() const
            {
                // No data to copy
                return ParmsRequest();
            }

            ParmsRequest(ParmsRequest &&source) = default;

            ParmsRequest &operator =(ParmsRequest &&source) = default;

        private:
            ParmsRequest() = default;
        };

        class OPRFRequest
        {
        friend class Sender;

        public:
            OPRFRequest(std::unique_ptr<network::SenderOperation> sop);

            OPRFRequest deep_copy() const
            {
                OPRFRequest result;
                result.data_ = data_;
                return std::move(result);
            }

            OPRFRequest(OPRFRequest &&source) = default;

            OPRFRequest &operator =(OPRFRequest &&source) = default;

        private:
            OPRFRequest() = default;

            std::vector<seal::SEAL_BYTE> data_;
        };

        class QueryRequest
        {
        friend class Sender;

        public:
            QueryRequest(std::unique_ptr<network::SenderOperation> sop);

            QueryRequest deep_copy() const
            {
                QueryRequest result;
                result.relin_keys_ = relin_keys_;
                result.data_ = data_;

                return std::move(result);
            }

            QueryRequest(QueryRequest &&source) = default;

            QueryRequest &operator =(QueryRequest &&source) = default;

        private:
            QueryRequest() = default;

            seal::RelinKeys relin_keys_;

            std::unordered_map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> data_;
        };

        // An alias to denote the powers of a receiver's ciphertext. At index i, holds Cⁱ, where C is the ciphertext..
        // The 0th index is always a dummy value.
        using CiphertextPowers = std::vector<seal::Ciphertext>;

        struct WindowingDag
        {
            enum class NodeState
            {
                Uncomputed = 0,
                Computing = 1,
                Done = 2
            };

            struct State
            {
                // The counter used to keep track of which nodes need to get compute (meaning the product of their input
                // has to be calculated)
                std::unique_ptr<std::atomic<std::size_t>> next_node;
                // All the node states
                std::unique_ptr<std::atomic<NodeState>[]> node_states;

                State(WindowingDag &dag);
            };

            struct Node
            {
                std::array<std::size_t, 2> inputs;
                std::size_t output = 0;
            };

            /**
            Stores the actual nodes of the DAG
            */
            std::vector<Node> nodes_;

            /**
            The windowing base
            */
            std::uint32_t base_;

            /**
            The largest ciphertext exponent we need to calculate
            */
            std::size_t max_exponent_;

            /**
            Constructs a directed acyclic graph, where each node has 2 inputs and 1 output. Every node has inputs i,j
            and output i+j. The largest power has exponent max_exponent. The choice of inputs depends on their Hamming
            weights, which depends on the base specified (the base is also known as the window size, and MUST be a power
            of 2). This is used to compute powers of a given ciphertext while minimizing circuit depth. The nodes vector
            is sorted in increasing order of Hamming weight of output.
            */
            WindowingDag(std::size_t max_exponent, std::uint32_t base);
        }; // struct WindowingDag

        class Sender
        {
        public:
            Sender() = delete;

            /**
            Generate and send a response to a parameter request.
            */
            static void RunParms(
                ParmsRequest &&parms_request,
                std::shared_ptr<SenderDB> sender_db,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>);

            /**
            Generate and send a response to an OPRF request.
            */
            static void RunOPRF(
                OPRFRequest &&oprf_request,
                const oprf::OPRFKey &key,
                std::shared_ptr<SenderDB> sender_db,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>);

            /**
            Generate and send a response to a query.
            */
            static void RunQuery(
                QueryRequest &&query_request,
                std::shared_ptr<SenderDB> sender_db,
                network::Channel &chl,
                std::size_t thread_count = 0,
                std::function<void(network::Channel &, std::unique_ptr<network::SenderOperationResponse>)> send_fun
                    = BasicSend<network::SenderOperationResponse>,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_rp_fun
                    = BasicSend<network::ResultPackage>);

        private:
            template<typename T>
            static void BasicSend(network::Channel &chl, std::unique_ptr<T> pkg)
            {
                chl.send(std::move(pkg));
            }

            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            static void QueryWorker(
                const std::shared_ptr<SenderDB> &sender_db,
                std::pair<std::uint32_t, std::uint32_t> bundle_idx_bounds,
                std::vector<std::vector<seal::Ciphertext>> &powers,
                WindowingDag &dag, std::vector<WindowingDag::State> &states,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_rp_fun);

            /**
            Constructs all powers of receiver's items for the specified batch, based on the powers sent from the
            receiver. For example, if the desired highest exponent (determined by PSIParams) is 15, the input exponents
            are {1, 2, 4, 8}, then this function will compute powers from 0 to 15, by multiplying appropriate powers in
            {1, 2, 4, 8}.

            See comment in sender.cpp for more detail.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items
            of the same power (y^k). The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input for the specified batch.
            */
            static void ComputePowers(
                const std::shared_ptr<SenderDB> &sender_db,
                CiphertextPowers &powers,
                const WindowingDag &dag,
                WindowingDag::State &state);
        }; // class Sender
    }      // namespace sender
} // namespace apsi
