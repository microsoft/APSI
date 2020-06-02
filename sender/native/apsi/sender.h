// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <atomic>
#include <deque>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

// GSL
#include <gsl/span>

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/item.h"
#include "apsi/network/channel.h"
#include "apsi/psiparams.h"
#include "apsi/senderdb.h"
#include "apsi/sendersessioncontext.h"
#include "apsi/tools/matrixview.h"

// SEAL
#include <seal/ciphertext.h>
#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/memorymanager.h>

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
                std::unique_ptr<std::atomic<int>> next_node;
                std::unique_ptr<std::atomic<NodeState>[]> node_state_storage;
                gsl::span<std::atomic<NodeState>> nodes;

                State(WindowingDag &dag);
            };

            struct Node
            {
                std::array<int, 2> inputs;
                int output = 0;
            };

            int max_power, window;
            std::uint64_t max_degree_supported; // maximum degree supported.
            std::uint64_t given_digits;         // how many digits are given.
            std::vector<int> base_powers;
            std::vector<Node> nodes;

            WindowingDag(int max_power, int window, std::uint64_t max_degree_supported, std::uint64_t given_digits)
                : max_power(max_power), window(window), max_degree_supported(max_degree_supported),
                  given_digits(given_digits)
            {
                std::uint64_t base = std::uint64_t(1) << window;
                std::uint64_t actual_power = tools::maximal_power(max_degree_supported, given_digits, base);

                logging::Log::debug("actual power supported = %i", actual_power);
                if (static_cast<int>(actual_power) < max_power)
                {
                    throw std::invalid_argument("does not support such max_power");
                }

                compute_dag();
            }

            std::uint64_t pow(std::uint64_t base, std::uint64_t e);
            std::uint64_t optimal_split(std::size_t x, int base, std::vector<int> &degrees);
            std::vector<std::uint64_t> conversion_to_digits(std::uint64_t input, int base);
            void compute_dag();
        }; // struct WindowingDag

        class Sender
        {
        public:
            Sender(const PSIParams &params, int thread_count);

            /**
            Clears data in sender's database.
            */
            inline void clear_db()
            {
                sender_db_.reset();
            }

            inline void set_db(std::shared_ptr<SenderDB> sender_db)
            {
                sender_db_ = sender_db;
                params_.set_split_count(sender_db_->get_params().split_count());
                params_.set_sender_bin_size(sender_db_->get_params().sender_bin_size());
            }

            /**
            Generate a response to a query
            */
            void query(
                const std::string &relin_keys, const std::map<std::uint64_t, std::vector<std::string>> query,
                const std::vector<seal::SEAL_BYTE> &client_id, network::Channel &channel);

            /**
            Return a reference to the PSI parameters used by the Sender
            */
            const PSIParams &get_params() const
            {
                return params_;
            }

            /**
            Return the SEALContext
            */
            std::shared_ptr<seal::SEALContext> get_seal_context()
            {
                return seal_context_;
            }

        private:
            /**
            Adds the data items to sender's database.
            */
            inline void add_data(const std::vector<Item> &data)
            {
                sender_db_->add_data(data, thread_count_);
            }

            /**
            Adds one item to sender's database.
            */
            inline void add_data(const Item &item)
            {
                sender_db_->add_data(item, thread_count_);
            }

            /**
            Responds to a query from the receiver. Input is a map of powers of receiver's items, from k to y^k, where k
            is an exponent, y is an item in receiver's cuckoo hashing table.

            Returns (#splits x #batches) ciphertexts, each of which is a result of the compute_dot_product function.

            @see compute_dot_product for an explanation of the result.
            */
            void respond(
                std::vector<std::vector<seal::Ciphertext>> &query, int num_of_powers,
                SenderSessionContext &session_context, const std::vector<seal::SEAL_BYTE> &client_id,
                network::Channel &channel);

            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            void respond_worker(
                int thread_index, int batch_count, int total_threads, int total_blocks,
                std::promise<void> &batches_done_prom, std::shared_future<void> &batches_done_fut,
                std::vector<std::vector<seal::Ciphertext>> &powers, SenderSessionContext &session_context,
                WindowingDag &dag, std::vector<WindowingDag::State> &states, std::atomic<int> &remaining_batches,
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
                int batch, std::vector<seal::Ciphertext> &batch_powers, SenderSessionContext &session_context,
                const WindowingDag &dag, WindowingDag::State &state, seal::MemoryPoolHandle pool);

            PSIParams params_;

            int thread_count_;

            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<SenderDB> sender_db_;
        }; // class Sender
    }      // namespace sender
} // namespace apsi
