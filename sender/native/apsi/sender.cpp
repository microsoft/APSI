// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <chrono>
#include <climits>
#include <future>
#include <numeric>
#include <thread>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/network_utils.h"
#include "apsi/result_package.h"
#include "apsi/sender.h"
#include "apsi/tools/utils.h"

// SEAL
#include <seal/modulus.h>
#include <seal/util/common.h>

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace logging;
    using namespace tools;
    using namespace network;

    namespace sender
    {
        Sender::Sender(const PSIParams &params, int thread_count)
            : params_(params), thread_count_(thread_count),
              seal_context_(SEALContext::Create(params_.encryption_params()))
        {}

        void Sender::query(
            const string &relin_keys, const map<u64, vector<string>> query, const vector<SEAL_BYTE> &client_id,
            Channel &channel)
        {
            if (!sender_db_)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stop_watch, "Sender::query");
            Log::info("Start processing query");

            // Load the relinearization keys from string
            RelinKeys rlk;
            get_relin_keys(seal_context_, rlk, relin_keys);

            // Create the session context
            SenderSessionContext session_context(seal_context_);
            session_context.set_relin_keys(rlk);
            session_context.set_ffield({ params_.ffield_characteristic(), params_.ffield_degree() });

            /* Receive client's query data. */
            int num_of_powers = static_cast<int>(query.size());
            Log::debug("Number of powers: %i", num_of_powers);
            Log::debug("Current batch count: %i", params_.batch_count());

            vector<vector<Ciphertext>> powers(params_.batch_count());
            auto split_size_plus_one = params_.split_size() + 1;

            for (size_t i = 0; i < powers.size(); ++i)
            {
                powers[i].reserve(split_size_plus_one);
                for (size_t j = 0; j < split_size_plus_one; ++j)
                {
                    powers[i].emplace_back(seal_context_);
                }
            }

            for (const auto &q : query)
            {
                size_t power = static_cast<size_t>(q.first);
                for (size_t i = 0; i < powers.size(); i++)
                {
                    get_ciphertext(seal_context_, powers[i][power], q.second[i]);
                }
            }

            /* Answer the query. */
            respond(powers, num_of_powers, session_context, client_id, channel);

            Log::info("Finished processing query");
        }

        void Sender::respond(
            vector<vector<Ciphertext>> &powers, int num_of_powers, SenderSessionContext &session_context,
            const vector<SEAL_BYTE> &client_id, Channel &channel)
        {
            STOPWATCH(sender_stop_watch, "Sender::respond");

            auto batch_count = params_.batch_count();
            int split_size_plus_one = params_.split_size() + 1;
            int total_blocks = params_.split_count() * batch_count;

            // Make the ciphertext non-transparent
            powers[0][0].resize(2);
            for (size_t i = 0; i < powers[0][0].coeff_modulus_size(); i++)
            {
                powers[0][0].data(1)[i * powers[0][0].poly_modulus_degree()] = 1;
            }

            // Create a dummy encryption of 1 and duplicate to all batches
            session_context.evaluator()->add_plain_inplace(powers[0][0], Plaintext("1"));
            for (size_t i = 1; i < powers.size(); i++)
            {
                powers[i][0] = powers[0][0];
            }

            int max_supported_degree = params_.max_supported_degree();
            int window_size = get_params().window_size();
            int base = 1 << window_size;

            // Ceiling of num_of_powers / (base - 1)
            int given_digits = (num_of_powers + base - 2) / (base - 1);

            WindowingDag dag(params_.split_size(), params_.window_size(), max_supported_degree, given_digits);

            std::vector<WindowingDag::State> states;
            states.reserve(batch_count);
            for (u64 i = 0; i < batch_count; i++)
            {
                states.emplace_back(dag);
            }

            atomic<int> remaining_batches(thread_count_);
            promise<void> batches_done_prom;
            auto batches_done_fut = batches_done_prom.get_future().share();

            vector<thread> thread_pool;
            for (size_t i = 0; i < thread_count_; i++)
            {
                thread_pool.emplace_back([&, i]() {
                    respond_worker(
                        static_cast<int>(i), batch_count, static_cast<int>(thread_count_), total_blocks,
                        batches_done_prom, batches_done_fut, powers, session_context, dag, states, remaining_batches,
                        client_id, channel);
                });
            }

            for (size_t i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i].join();
            }
        }

        void Sender::respond_worker(
            int thread_index, int batch_count, int total_threads, int total_blocks, promise<void> &batches_done_prom,
            shared_future<void> &batches_done_fut, vector<vector<Ciphertext>> &powers,
            SenderSessionContext &session_context, WindowingDag &dag, vector<WindowingDag::State> &states,
            atomic<int> &remaining_batches, const vector<SEAL_BYTE> &client_id, Channel &channel)
        {
            STOPWATCH(sender_stop_watch, "Sender::respond_worker");

            /* Multiple client sessions can enter this function to compete for thread context resources. */
            auto local_pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);

            Ciphertext tmp(local_pool);
            Ciphertext compressedResult(seal_context_, local_pool);

            u64 batch_start = thread_index * batch_count / total_threads;
            auto thread_idx = std::this_thread::get_id();

            for (int batch = static_cast<int>(batch_start), loop_idx = 0ul; loop_idx < batch_count; ++loop_idx)
            {
                compute_batch_powers(
                    static_cast<int>(batch), powers[batch], session_context, dag, states[batch], local_pool);
                batch = (batch + 1) % batch_count;
            }

            auto count = remaining_batches--;
            if (count == 1)
            {
                batches_done_prom.set_value();
            }
            else
            {
                batches_done_fut.get();
            }

            int start_block = thread_index * total_blocks / thread_count_;
            int end_block = (thread_index + 1) * total_blocks / thread_count_;

            // Constuct two ciphertexts to store the result. One keeps track of the current result,
            // one is used as a temp. Their roles switch each iteration. Saved needing to make a
            // copy in eval->add(...)
            array<Ciphertext, 2> runningResults{ local_pool, local_pool }, label_results{ local_pool, local_pool };

            u64 processed_blocks = 0;
            Evaluator &evaluator = *session_context.evaluator();
            for (int block_idx = start_block; block_idx < end_block; block_idx++)
            {
                int batch = block_idx / params_.split_count(), split = block_idx % params_.split_count();
                auto &block = sender_db_->get_block(batch, split);

                // Get the pointer to the first poly of this batch.
                // Plaintext* sender_coeffs(&sender_db_.batch_random_symm_polys()[split * splitStep + batch *
                // split_size_plus_one]);

                // Iterate over the coeffs multiplying them with the query powers  and summing the results
                u8 currResult = 0, curr_label = 0;

                // TODO: optimize this to allow low degree poly? need to take into account noise levels.

                // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                // Observe that the first call to mult is always multiplying coeff[0] by 1....
                // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt

                evaluator.multiply_plain(
                    powers[batch][0], block.batch_random_symm_poly_[0], runningResults[currResult]);

                for (u32 s = 1; s < params_.split_size(); s++)
                {
                    // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call
                    // multiply_plain_ntt
                    evaluator.multiply_plain(powers[batch][s], block.batch_random_symm_poly_[s], tmp);
                    evaluator.add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);
                    currResult ^= 1;
                }

                // Handle the case for s = params_.split_size();
                int s = params_.split_size();
                tmp = powers[batch][s];
                evaluator.add(tmp, runningResults[currResult], runningResults[currResult ^ 1]);
                currResult ^= 1;

                if (params_.use_labels())
                {
                    if (block.batched_label_coeffs_.size() > 1)
                    {
                        STOPWATCH(sender_stop_watch, "Sender::respond_worker::online_interpolate");

                        // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                        // Observe that the first call to mult is always multiplying coeff[0] by 1....

                        // TODO: edge case where all block.batched_label_coeffs_[s] are zero.

                        // label_result = coeff[0] * x^0 = coeff[0];
                        size_t s = 0;
                        while (s < block.batched_label_coeffs_.size() && block.batched_label_coeffs_[s].is_zero())
                            ++s;

                        // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call
                        // multiply_plain_ntt

                        if (s < block.batched_label_coeffs_.size())
                        {
                            evaluator.multiply_plain(
                                powers[batch][s], block.batched_label_coeffs_[s], label_results[curr_label]);
                        }
                        else
                        {
                            session_context.encryptor_->encrypt_zero(label_results[curr_label]);
                            evaluator.transform_to_ntt_inplace(label_results[curr_label]);
                            // just set it to be an encryption of zero.
                            // encryptor_->encrypt;
                        }

                        while (++s < block.batched_label_coeffs_.size())
                        {
                            // label_result += coeff[s] * x^s;
                            if (block.batched_label_coeffs_[s].is_zero() == false)
                            {
                                // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call
                                // multiply_plain_ntt
                                evaluator.multiply_plain(powers[batch][s], block.batched_label_coeffs_[s], tmp);
                                evaluator.add(tmp, label_results[curr_label], label_results[curr_label ^ 1]);
                                curr_label ^= 1;
                            }
                        }
                    }
                    else if (block.batched_label_coeffs_.size() && !block.batched_label_coeffs_[0].is_zero())
                    {
                        // only reachable if user calls PSIParams.set_use_low_degree_poly(true);

                        // TODO: This can be optimized to reduce the number of multiply_plain_ntt by 1.
                        // Observe that the first call to mult is always multiplying coeff[0] by 1....

                        // TODO: edge case where block.batched_label_coeffs_[0] is zero.

                        // IMPORTANT: Both inputs are in NTT transformed form so internally SEAL will call
                        // multiply_plain_ntt
                        evaluator.multiply_plain(
                            powers[batch][0], block.batched_label_coeffs_[0], label_results[curr_label]);
                    }
                    else
                    {
                        // only reachable if user calls PSIParams.set_use_low_degree_poly(true);
                        // doesn't matter what we set... this will due.
                        label_results[curr_label] = powers[batch][0];
                    }

                    // TODO: We need to randomize the result. This is fine for now.
                    evaluator.add(runningResults[currResult], label_results[curr_label], label_results[curr_label ^ 1]);
                    curr_label ^= 1;

                    evaluator.transform_from_ntt_inplace(label_results[curr_label]);
                }

                // Transform back from ntt form.
                evaluator.transform_from_ntt_inplace(runningResults[currResult]);

                // Send the result over the network if needed.

                // First compress
                CiphertextCompressor &compressor = *session_context.compressor();
                compressor.mod_switch(runningResults[currResult], compressedResult);

                // Send the compressed result
                ResultPackage pkg;
                pkg.split_idx = split;
                pkg.batch_idx = batch;

                {
                    stringstream ss;
                    compressor.compressed_save(compressedResult, ss);
                    pkg.data = ss.str();
                }

                if (params_.use_labels())
                {
                    // Compress label
                    compressor.mod_switch(label_results[curr_label], compressedResult);

                    stringstream ss;
                    compressor.compressed_save(compressedResult, ss);
                    pkg.label_data = ss.str();
                }

                channel.send(client_id, pkg);
                processed_blocks++;
            }

            Log::debug("Thread %d sent %d blocks", thread_index, processed_blocks);
        }

        void Sender::compute_batch_powers(
            int batch, vector<Ciphertext> &batch_powers, SenderSessionContext &session_context, const WindowingDag &dag,
            WindowingDag::State &state, MemoryPoolHandle pool)
        {
            auto thrdIdx = std::this_thread::get_id();

            if (batch_powers.size() != params_.split_size() + 1)
            {
                std::cout << batch_powers.size() << " != " << params_.split_size() + 1 << std::endl;
                throw std::runtime_error("");
            }

            size_t idx = (*state.next_node)++;
            Evaluator &evaluator = *session_context.evaluator();
            while (idx < dag.nodes.size())
            {
                auto &node = dag.nodes[idx];
                auto &node_state = state.nodes[node.output];

                // a simple write should be sufficient but lets be safe
                auto exp = WindowingDag::NodeState::Ready;
                bool r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Pending);
                if (r == false)
                {
                    std::cout << int(exp) << std::endl;
                    throw std::runtime_error("");
                }

                // spin lock on the input nodes
                for (size_t i = 0; i < 2; i++)
                {
                    while (state.nodes[node.inputs[i]] != WindowingDag::NodeState::Done)
                        ;
                }

                evaluator.multiply(
                    batch_powers[node.inputs[0]], batch_powers[node.inputs[1]], batch_powers[node.output], pool);
                evaluator.relinearize_inplace(batch_powers[node.output], session_context.relin_keys_, pool);

                // a simple write should be sufficient but lets be safe
                exp = WindowingDag::NodeState::Pending;
                r = node_state.compare_exchange_strong(exp, WindowingDag::NodeState::Done);
                if (r == false)
                {
                    throw std::runtime_error("");
                }

                idx = (*state.next_node)++;
            }

            // Iterate until all nodes are computed. We may want to do something smarter here.
            for (int i = 0; i < state.nodes.size(); ++i)
            {
                while (state.nodes[i] != WindowingDag::NodeState::Done)
                    ;
            }

            auto end = dag.nodes.size() + batch_powers.size();
            while (idx < end)
            {
                auto i = idx - dag.nodes.size();

                evaluator.transform_to_ntt_inplace(batch_powers[i]);
                idx = (*state.next_node)++;
            }
        }

        u64 WindowingDag::pow(u64 base, u64 e)
        {
            u64 r = 1;
            while (e--)
                r *= base;
            return r;
        }

        u64 WindowingDag::optimal_split(size_t x, int base, vector<int> &degrees)
        {
            int opt_deg = degrees[x];
            int opt_split = 0;

            for (size_t i1 = 1; i1 < x; i1++)
            {
                if (degrees[i1] + degrees[x - i1] < opt_deg)
                {
                    opt_split = static_cast<int>(i1);
                    opt_deg = degrees[i1] + degrees[x - i1];
                }
                else if (
                    degrees[i1] + degrees[x - i1] == opt_deg &&
                    abs(degrees[i1] - degrees[x - i1]) < abs(degrees[opt_split] - degrees[x - opt_split]))
                {
                    opt_split = static_cast<int>(i1);
                }
            }

            degrees[x] = opt_deg;

            return opt_split;
        }

        vector<u64> WindowingDag::conversion_to_digits(u64 input, int base)
        {
            vector<u64> result;
            while (input > 0)
            {
                result.push_back(input % base);
                input /= base;
            }
            return result;
        }

        void WindowingDag::compute_dag()
        {
            vector<int> degree(max_power + 1, numeric_limits<int>::max());
            vector<int> splits(max_power + 1);
            vector<int> items_per(max_power, 0);

            Log::debug("Computing windowing dag: max power = %i", max_power);

            // initialize the degree array.
            // given digits...
            int base = (1 << window);
            for (int i = 0; i < given_digits; i++)
            {
                for (int j = 1; j < base; j++)
                {
                    if (pow(base, i) * j < degree.size())
                    {
                        degree[static_cast<size_t>(pow(base, i) * j)] = 1;
                    }
                }
            }

            degree[0] = 0;

            for (int i = 1; i <= max_power; i++)
            {
                int i1 = static_cast<int>(optimal_split(i, 1 << window, degree));
                int i2 = i - i1;
                splits[i] = i1;

                if (i1 == 0 || i2 == 0)
                {
                    base_powers.emplace_back(i);
                    degree[i] = 1;
                }
                else
                {
                    degree[i] = degree[i1] + degree[i2];
                    ++items_per[degree[i]];
                }
                Log::debug("degree[%i] = %i", i, degree[i]);
                Log::debug("splits[%i] = %i", i, splits[i]);
            }

            // Validate the we did not exceed maximal supported degree.
            if (*std::max_element(degree.begin(), degree.end()) > max_degree_supported)
            {
                Log::error("Degree exceeds maximal supported");
                throw invalid_argument("degree too large");
            }

            for (int i = 3; i < max_power && items_per[i]; i++)
            {
                items_per[i] += items_per[i - 1];
            }

            for (int i = 0; i < max_power; i++)
            {
                Log::debug("items_per[%i] = %i", i, items_per[i]);
            }

            // size = how many powers we still need to generate.
            int size = static_cast<int>(max_power - base_powers.size());
            nodes.resize(size);

            for (int i = 1; i <= max_power; i++)
            {
                int i1 = splits[i];
                int i2 = i - i1;

                if (i1 && i2) // if encryption(y^i) is not given
                {
                    auto d = degree[i] - 1;

                    auto idx = items_per[d]++;
                    if (nodes[idx].output)
                    {
                        throw std::runtime_error("");
                    }

                    nodes[idx].inputs = { i1, i2 };
                    nodes[idx].output = i;
                }
            }
        }

        WindowingDag::State::State(WindowingDag &dag)
        {
            next_node = make_unique<std::atomic<int>>();
            *next_node = 0;
            node_state_storage = make_unique<std::atomic<NodeState>[]>(dag.max_power + 1);
            nodes = { node_state_storage.get(), static_cast<size_t>(dag.max_power + 1) };

            for (auto &n : nodes)
            {
                n = NodeState::Ready;
            }

            nodes[0] = NodeState::Done;
            for (auto &n : dag.base_powers)
            {
                nodes[n] = NodeState::Done;
            }
        }
    } // namespace sender
} // namespace apsi
