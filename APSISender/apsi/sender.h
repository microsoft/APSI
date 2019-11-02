// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <deque>
#include <mutex>
#include <memory>
#include <vector>
#include <iostream>
#include <map>
#include <future>

// GSL
#include <gsl/span>

// APSI
#include "apsi/item.h"
#include "apsi/psiparams.h"
#include "apsi/senderdb.h"
#include "apsi/sendersessioncontext.h"
#include "apsi/senderthreadcontext.h"
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_fast_batch_encoder.h"
#include "apsi/tools/sealcompress.h"
#include "apsi/tools/matrixview.h"
#include "apsi/network/channel.h"

// SEAL
#include "seal/encryptionparams.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/evaluator.h"


namespace apsi
{
    namespace sender
    {
        struct WindowingDag
        {
            enum class NodeState {
                Ready = 0,
                Pending = 1,
                Done = 2
            };

            struct State
            {
                std::unique_ptr<std::atomic<int>> next_node_;
                std::unique_ptr<std::atomic<NodeState>[]> node_state_storage_;
                gsl::span<std::atomic<NodeState>> nodes_;

                State(WindowingDag& dag);
            };

            struct Node
            {
                std::array<int, 2> inputs_;
                int output_ = 0;
            };

            int max_power_, window_;
            int max_degree_supported_; // maximum degree supported.
            int given_digits_;  // how many digits are given. 
            std::vector<int> base_powers_;
            std::vector<Node> nodes_;

            WindowingDag(int max_power, int window, int max_degree_supported, int given_digits)
            {
                max_power_ = max_power;
                window_ = window;
                int base = 1 << window_;
                max_degree_supported_ = max_degree_supported;
                given_digits_ = given_digits;
                u64 actual_power = tools::maximal_power(max_degree_supported, given_digits, base);

                apsi::logging::Log::debug("actual power supported = %i", actual_power);

                if (static_cast<int>(actual_power) < max_power)
                {
                    throw std::invalid_argument("does not support such max_power");
                }

                compute_dag();
            }

            u64 pow(u64 base, u64 e);
            uint64_t optimal_split(std::size_t x, int base, std::vector<int> &degrees);
            std::vector<uint64_t> conversion_to_digits(uint64_t input, int base);
            void compute_dag();
        };

        class Sender
        {
        public:
            Sender(const PSIParams &params,
                int total_thread_count,
                int session_thread_count,
                seal::MemoryPoolHandle pool = seal::MemoryPoolHandle::Global());

            /**
            Clears data in sender's database.
            */
            inline void clear_db()
            {
                sender_db_->clear_db();
            }

            /**
            Loads the input data into sender's database, and precomputes all necessary components for the PSI protocol,
            including symmetric polynomials, batching, etc.
            */
            void load_db(const std::vector<Item> &data, MatrixView<u8> vals = {});

            /**
            Generate a response to a query
            */
            void query(
                const std::string& relin_keys,
                const std::map<apsi::u64, std::vector<std::string>> query,
                const std::vector<apsi::u8>& client_id,
                apsi::network::Channel& channel);

            /**
            Return a reference to the PSI parameters used by the Sender
            */
            const apsi::PSIParams& get_params() const { return params_; }

            /**
            Return the SEALContext
            */
            std::shared_ptr<seal::SEALContext> get_seal_context()
            {
                return seal_context_;
            }

        private:
            void initialize();

            int acquire_thread_context();

            void release_thread_context(int idx);

            /**
            Adds the data items to sender's database.
            */
            inline void add_data(const std::vector<Item> &data)
            {
                sender_db_->add_data(data, total_thread_count_);
            }

            /**
            Adds one item to sender's database.
            */
            inline void add_data(const Item &item)
            {
                sender_db_->add_data(item, total_thread_count_);
            }

            /**
            Precomputes all necessary components for the PSI protocol, including symmetric polynomials, batching, etc.
            This function is expensive and can be called after sender finishes adding items to the database.
            */
            void offline_compute();

            /**
            Handles work for offline_compute for a single thread.
            */
            void offline_compute_work();

            /**
            Report progress of the offline_compute operation.
            Progress is reported to the Log.
            */
            void report_offline_compute_progress(int total_threads, std::atomic<bool>& work_finished);

            /**
            Responds to a query from the receiver. Input is a map of powers of receiver's items, from k to y^k, where k is an
            exponent, y is an item in receiver's cuckoo hashing table.

            Returns (#splits x #batches) ciphertexts, each of which is a result of the compute_dot_product function.

            @see compute_dot_product for an explanation of the result.
            */
            void respond(
                std::vector<std::vector<seal::Ciphertext> > &query, int num_of_powers,
                apsi::sender::SenderSessionContext &session_context,
                const std::vector<apsi::u8>& client_id,
                apsi::network::Channel& channel);

            /**
            Method that handles the work of a single thread that computes the response to a query.
            */
            void respond_worker(
                int batch_count,
                int total_threads,
                int total_blocks,
                std::promise<void>& batches_done_prom,
                std::shared_future<void>& batches_done_fut,
                std::vector<std::vector<seal::Ciphertext>>& powers,
                apsi::sender::SenderSessionContext &session_context,
                apsi::sender::WindowingDag& dag,
                std::vector<apsi::sender::WindowingDag::State>& states,
                std::atomic<int>& remaining_batches,
                const std::vector<apsi::u8>& client_id,
                apsi::network::Channel& channel);


            /**
            Constructs all powers of receiver's items for the specified batch, based on the powers sent from the receiver. For example, if the
            desired highest exponent (determined by PSIParams) is 15, the input exponents are {1, 2, 4, 8}, then this function will compute powers
            from 0 to 15, by multiplying appropriate powers in {1, 2, 4, 8}.

            @params[in] input Map from exponent (k) to a vector of Ciphertext, each of which encrypts a batch of items of the same power (y^k).
            The size of the vector is the number of batches.
            @params[out] all_powers All powers computed from the input for the specified batch.
            */
            void compute_batch_powers(int batch, std::vector<seal::Ciphertext> &batch_powers,
                SenderSessionContext &session_context, SenderThreadContext &thread_context,
                const WindowingDag& dag, WindowingDag::State& state);

            PSIParams params_;

            int total_thread_count_;

            int session_thread_count_;

            seal::MemoryPoolHandle pool_;

            FField field_;

            std::shared_ptr<seal::SEALContext> seal_context_;

            std::shared_ptr<seal::Evaluator> evaluator_;

            std::shared_ptr<FFieldFastBatchEncoder> ex_batch_encoder_;

            // Objects for compressed ciphertexts
            std::shared_ptr<CiphertextCompressor> compressor_;

            /* Sender's database, including raw data, hashed data, ExField data, and symmetric polynomials. */
            std::unique_ptr<SenderDB> sender_db_;

            /* One context for one thread, to improve preformance by using single-thread memory pool. */
            std::vector<SenderThreadContext> thread_contexts_;

            std::deque<int> available_thread_contexts_;

            std::mutex thread_context_mtx_;
        };
    }
}
