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

// GSL
#include <gsl/span>

// APSI
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/psiparams.h"
#include "apsi/senderdb.h"
#include "apsi/sendersessioncontext.h"

// SEAL
#include <seal/ciphertext.h>
#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/memorymanager.h>
#include <seal/util/locks.h>

namespace apsi
{
    namespace sender
    {
        struct WindowingDag
        {
            enum class NodeState
            {
                Ready = 0,
                Pending = 1,
                Done = 2
            };

            struct State
            {
                std::unique_ptr<std::atomic<std::size_t>> next_node;
                std::unique_ptr<std::atomic<NodeState>[]> node_state_storage;
                gsl::span<std::atomic<NodeState>> nodes;

                State(WindowingDag &dag);
            };

            struct Node
            {
                std::array<std::size_t, 2> inputs;
                std::size_t output = 0;
            };

            std::size_t max_power;
            std::uint32_t window;
            std::uint32_t given_digits;
            std::vector<std::uint32_t> base_powers;
            std::vector<Node> nodes;

            WindowingDag(
                std::size_t max_power, std::uint32_t window, std::uint32_t given_digits)
                : max_power(max_power), window(window), given_digits(given_digits)
            {
                compute_dag();
            }

            std::uint64_t pow(std::uint64_t base, std::uint64_t e);
            std::size_t optimal_split(std::size_t x, std::vector<std::uint32_t> &degrees);
            std::vector<std::uint64_t> conversion_to_digits(std::uint64_t input, std::uint32_t base);
            void compute_dag();
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
                const std::string &relin_keys, const std::map<std::uint64_t, std::vector<std::string>> &query,
                const std::vector<seal::SEAL_BYTE> &client_id, network::Channel &channel);

            /**
            Return a reference to the PSI parameters used by the Sender.
            */
            const PSIParams &get_params() const
            {
                return params_;
            }

        private:
            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            void query_worker(
                std::pair<std::size_t, std::size_t> bundle_idx_bounds,
                std::vector<std::vector<seal::Ciphertext>> &powers, const CryptoContext &crypto_context,
                WindowingDag &dag, std::vector<WindowingDag::State> &states,
                const std::vector<seal::SEAL_BYTE> &client_id, network::Channel &channel);

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
                std::vector<seal::Ciphertext> &batch_powers, CryptoContext &crypto_context,
                const WindowingDag &dag, WindowingDag::State &state);

            PSIParams params_;

            std::size_t thread_count_;

            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<SenderDB> sender_db_;

            /**
            Read-write lock for controlling access to the database.
            */
            seal::util::ReaderWriterLocker sender_db_lock_;
        }; // class Sender
    }      // namespace sender
} // namespace apsi
