// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <atomic>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <utility>
#include <string>
#include <functional>

// GSL
#include "gsl/span"

// APSI
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/psiparams.h"
#include "apsi/senderdb.h"
#include "apsi/cryptocontext.h"
#include "apsi/sealobject.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/locks.h"
#include "seal/relinkeys.h"
#include "seal/ciphertext.h"

namespace apsi
{
    namespace sender
    {
        // An alias to denote the powers of a ciphertext. For a ciphertext C, this holds C, C², C³, etc. It does not
        // hold C⁰.
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
                std::vector<std::atomic<NodeState> > node_states;

                State(WindowingDag &dag);
            };

            struct Node
            {
                std::array<std::size_t, 2> inputs;
                std::size_t output = 0;
            };

            std::vector<Node> nodes_;
            uint32_t base;

            /**
            Constructs a directed acyclic graph, where each node has 2 inputs and 1 output. Every node has inputs i,j
            and output i+j. The largest output size is max_power. The choice of inputs depends on their Hamming weights,
            which depends on the base specified.
            This is used to compute powers of a given ciphertext while minimizing circuit depth.  The nodes are sorted
            in increasing order of Hamming weight of their output.
            */
            WindowingDag(std::size_t max_power, std::uint32_t base);
        }; // struct WindowingDag

        class Sender
        {
        public:
            Sender(const PSIParams &params, std::size_t thread_count);

            /**
            Clears data in sender's database.
            */
            inline void clear_db()
            {
                auto lock = sender_db_lock_.acquire_write();
                sender_db_.reset();
            }

            /**
            Sets the database to be used.
            */
            inline void set_db(std::shared_ptr<SenderDB> sender_db)
            {
                auto lock = sender_db_lock_.acquire_write();
                sender_db_ = std::move(sender_db);
            }

            /**
            Generate a response to a query.
            */
            void query(
                seal::RelinKeys relin_keys,
                std::map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> query,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_fun = BasicSend);

            /**
            Return the PSI parameters.
            */
            const PSIParams &get_params() const
            {
                return params_;
            }

            /**
            Return the SEALContext.
            */
            std::shared_ptr<seal::SEALContext> get_seal_context() const
            {
                return seal_context_;
            }

            seal::util::ReaderLock get_reader_lock() const
            {
                return sender_db_lock_.acquire_read();
            }

            static void BasicSend(network::Channel &chl, std::unique_ptr<network::ResultPackage> rp)
            {
                chl.send(std::move(rp));
            }

        private:
            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            void query_worker(
                std::pair<std::uint32_t, std::uint32_t> bundle_idx_bounds,
                std::vector<std::vector<seal::Ciphertext>> &powers, const CryptoContext &crypto_context,
                WindowingDag &dag, std::vector<WindowingDag::State> &states,
                network::Channel &chl,
                std::function<void(network::Channel &, std::unique_ptr<network::ResultPackage>)> send_fun);

            /**
            Constructs all powers of receiver's items for the specified batch, based on the powers sent from the
            receiver. For example, if the desired highest exponent (determined by PSIParams) is 15, the input exponents
            are {1, 2, 4, 8}, then this function will compute powers from 0 to 15, by multiplying appropriate powers in
            {1, 2, 4, 8}.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items
            of the same power (y^k). The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input for the specified batch.
            */
            void compute_batch_powers(
                std::vector<seal::Ciphertext> &batch_powers, const CryptoContext &crypto_context,
                const WindowingDag &dag, WindowingDag::State &state);

            PSIParams params_;

            std::size_t thread_count_;

            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<SenderDB> sender_db_;

            /**
            Read-write lock for controlling access to the database.
            */
            mutable seal::util::ReaderWriterLocker sender_db_lock_;
        }; // class Sender
    }      // namespace sender
} // namespace apsi
