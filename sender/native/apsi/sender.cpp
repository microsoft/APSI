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
#include "apsi/util/utils.h"

// SEAL
#include <seal/modulus.h>
#include <seal/util/common.h>

using namespace std;
using namespace seal;

namespace apsi
{
    using namespace logging;
    using namespace util;
    using namespace network;

    namespace sender
    {
        Sender::Sender(const PSIParams &params, size_t thread_count)
            : params_(params), thread_count_(thread_count),
              seal_context_(SEALContext::Create(params_.encryption_params()))
        {}

        void Sender::query(
            const string &relin_keys, const map<uint64_t, vector<string>> &query, const vector<SEAL_BYTE> &client_id,
            Channel &channel)
        {
            if (!sender_db_)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stop_watch, "Sender::query");
            Log::info("Start processing query");

            // Create the session context
            SenderSessionContext session_context(seal_context_);

            // Load the relinearization keys from string
            get_relin_keys(seal_context_, rlk, session_context.relin_keys());

            /* Receive client's query data. */
            int num_of_powers = static_cast<int>(query.size());
            Log::debug("Number of powers: %i", num_of_powers);
            Log::debug("Current batch count: %i", params_.batch_count());

            // For each BinBundle index, we have a vector of powers of the query
            vector<vector<Ciphertext>> powers(params_.batch_count());
            auto split_size_plus_one = params_.split_size() + 1;

            // Initialize the powers matrix
            for (size_t i = 0; i < powers.size(); ++i)
            {
                powers[i].reserve(split_size_plus_one);
                for (size_t j = 0; j < split_size_plus_one; ++j)
                {
                    powers[i].emplace_back(seal_context_);
                }
            }

            // Load inputs provided in the query
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

            size_t batch_count = params_.batch_count();
            size_t total_blocks = params_.split_count() * batch_count;

            // powers[i][0] is supposed to be an encryption of 1 for each i; however, we don't have
            // the public key available. We will create instead a dummy encryption of zero by reserving
            // appropriate memory and adding some noise to it, and then add a plaintext 1 to it.
            powers[0][0].resize(2);
            for (size_t i = 0; i < powers[0][0].coeff_modulus_size(); i++)
            {
                // Add some noise to the ciphertext to make it non-transparent
                powers[0][0].data(1)[i * powers[0][0].poly_modulus_degree()] = 1;
            }

            // Create a dummy encryption of 1 and duplicate to all batches
            session_context.evaluator()->add_plain_inplace(powers[0][0], Plaintext("1"));
            for (size_t i = 1; i < powers.size(); i++)
            {
                // Replicate for each BinBundle index
                powers[i][0] = powers[0][0];
            }

            // Obtain the windowing information
            size_t window_size = get_params().window_size();
            uint32_t base = uint32_t(1) << window_size;

            // Ceiling of num_of_powers / (base - 1)
            uint32_t given_digits = (static_cast<uint32_t>(num_of_powers) + base - 2) / (base - 1);

            // Prepare the windowing information
            WindowingDag dag(static_cast<uint32_t>(params_.split_size()), params_.window_size(), given_digits);

            // Create a state per each BinBundle index; this contains information about whether the
            // powers for that BinBundle index have been computed
            std::vector<WindowingDag::State> states;
            states.reserve(batch_count);
            for (uint64_t i = 0; i < batch_count; i++)
            {
                states.emplace_back(dag);
            }

            // How many batches do we still need to compute the powers for
            atomic<size_t> remaining_batches(thread_count_);

            // A promise to signal the worker threads when all batches have been processed
            promise<void> batches_done_prom;

            // Get a shared future to be given to all worker threads so they know when all batches are done
            auto batches_done_fut = batches_done_prom.get_future().share();

            vector<thread> thread_pool;
            for (size_t i = 0; i < thread_count_; i++)
            {
                thread_pool.emplace_back([&, i]() {
                    respond_worker(
                        i, batch_count, thread_count_, total_blocks, batches_done_prom, batches_done_fut, powers,
                        session_context, dag, states, remaining_batches, client_id, channel);
                });
            }

            for (size_t i = 0; i < thread_pool.size(); i++)
            {
                thread_pool[i].join();
            }
        }

        void Sender::respond_worker(
            size_t thread_index,
            size_t batch_count,
            size_t total_threads,
            size_t total_blocks,
            promise<void> &batches_done_prom,
            shared_future<void> &batches_done_fut,
            vector<vector<Ciphertext>> &powers,
            SenderSessionContext &session_context,
            WindowingDag &dag,
            vector<WindowingDag::State> &states,
            atomic<int> &remaining_batches,
            const vector<SEAL_BYTE> &client_id,
            Channel &channel
        ) {
            STOPWATCH(sender_stop_watch, "Sender::respond_worker");

            /* Multiple client sessions can enter this function to compete for thread context resources. */
            auto local_pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);

            Ciphertext compressed_result(seal_context_, local_pool);

            // The BinBundle indices are split evenly between the different threads
            size_t batch_start = thread_index * batch_count / total_threads;
            for (size_t batch = batch_start, loop_idx = 0; loop_idx < batch_count; ++loop_idx)
            {
                compute_batch_powers(powers[batch], session_context, dag, states[batch], local_pool);

                // TODO: WHY???
                batch = (batch + 1) % batch_count;
            }

            // We are done processing this batch so atomically decrease the counter
            auto count = remaining_batches--;
            if (count == 1)
            {
                // All batches done! Ready to move on to the next phase
                batches_done_prom.set_value();
            }
            else
            {
                // Block until all BinBundle indices have been processed
                batches_done_fut.get();
            }

            // Divide the blocks for processing
            size_t start_block = thread_index * total_blocks / thread_count_;
            size_t end_block = (thread_index + 1) * total_blocks / thread_count_;

            // Construct two ciphertexts to store the result. One keeps track of the current result,
            // one is used as a temp. Their roles switch each iteration. Saved needing to make a
            // copy in evaluator->add(...)
            array<Ciphertext, 2> running_results{ local_pool, local_pool }, label_results{ local_pool, local_pool };

            Evaluator &evaluator = *session_context.evaluator();

            size_t processed_blocks = 0;
            for (size_t block_idx = start_block; block_idx < end_block; block_idx++)
            {
                // Find the batch index for the block currently processed
                size_t batch = block_idx / params_.split_count(), split = block_idx % params_.split_count();
                auto &block = sender_db_->get_block(batch, split);

                // Iterate over the coeffs multiplying them with the query powers and summing the results
                unsigned char curr_result = 0, curr_label = 0;

                // Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                // Note that powers[batch][0] is really just a dummy encryption of 1
                evaluator.multiply_plain(
                    powers[batch][0], block.batch_random_symm_poly_[0], running_results[curr_result]);

                Ciphertext temp(local_pool);
                for (size_t s = 1; s < params_.split_size(); s++)
                {
                    // Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                    evaluator.multiply_plain(powers[batch][s], block.batch_random_symm_poly_[s], temp);

                    evaluator.add(temp, running_results[curr_result], running_results[curr_result ^ 1]);
                    curr_result ^= 1;
                }

                // Handle the case for s = params_.split_size(); this is the highest degree component where
                // the corresponding plaintext would be 1. Instead of an unnecessary multiplication, we simply
                // add the leading power of the query to the result.
                evaluator.add(
                        powers[batch][params_.split_size()],
                        running_results[curr_result],
                        running_results[curr_result ^ 1]);
                curr_result ^= 1;

                if (params_.use_labels())
                {
                    // Do we have any label polynomial coefficients?
                    if (block.batched_label_coeffs_.size())
                    {
                        STOPWATCH(sender_stop_watch, "Sender::respond_worker::online_interpolate");

                        // First find the lowest-degree label coefficient that is non-zero
                        size_t s = 0;
                        while (s < block.batched_label_coeffs_.size() && block.batched_label_coeffs_[s].is_zero())
                        {
                            ++s;
                        }

                        // Compute dot product of the label polynomial coefficients with the query powers
                        if (s < block.batched_label_coeffs_.size())
                        {
                            // Multiply and write to label_results. Here we process only the lowest-degree product.
                            // Both inputs are in NTT transformed form so internally SEAL will call multiply_plain_ntt
                            evaluator.multiply_plain(
                                powers[batch][s], block.batched_label_coeffs_[s], label_results[curr_label]);
                        }
                        else // if s equals the number of label coefficients, i.e., if all coefficients were zero
                        {
                            // Write a zero as the label result
                            session_context.encryptor_->encrypt_zero(label_results[curr_label]);
                            evaluator.transform_to_ntt_inplace(label_results[curr_label]);
                        }

                        // Compute products and aggregate the rest of the coefficients
                        while (++s < block.batched_label_coeffs_.size())
                        {
                            // label_result += coeff[s] * x^s;
                            if (block.batched_label_coeffs_[s].is_zero() == false)
                            {
                                // Process only products where the label coefficient is non-zero to avoid
                                // transparent ciphertexts
                                evaluator.multiply_plain(powers[batch][s], block.batched_label_coeffs_[s], temp);
                                evaluator.add(temp, label_results[curr_label], label_results[curr_label ^ 1]);
                                curr_label ^= 1;
                            }
                        }
                    }
                    else
                    {
                        // No label polynomial coefficients are present
                        label_results[curr_label] = powers[batch][0];
                    }

                    // Randomize the result by adding the matching result
                    evaluator.add(running_results[curr_result], label_results[curr_label], label_results[curr_label ^ 1]);
                    curr_label ^= 1;

                    // Transform label result back from NTT form
                    evaluator.transform_from_ntt_inplace(label_results[curr_label]);
                }

                // Transform matching result back from NTT form
                evaluator.transform_from_ntt_inplace(running_results[curr_result]);

                // Send the compressed result
                ResultPackage pkg;
                pkg.bin_bundle_index = batch;

                // Modulus switch to the lowest level before saving
                CiphertextCompressor &compressor = *session_context.compressor();
                compressor.mod_switch(running_results[curr_result], compressed_result);

                stringstream ss;
                compressor.compressed_save(compressed_result, ss);
                pkg.data = ss.str();
                ss.seekp(0, ios::beg);

                if (params_.use_labels())
                {
                    // Modulus switch label to the lowest level before saving
                    compressor.mod_switch(label_results[curr_label], compressed_result);

                    compressor.compressed_save(compressed_result, ss);
                    pkg.label_data = ss.str();
                }

                // Start sending on the channel
                channel.send(client_id, pkg);

                // Done with this block; atomically increase processed_blocks
                processed_blocks++;
            }

            Log::debug("Thread %d sent %d blocks", thread_index, processed_blocks);
        }

        void Sender::compute_batch_powers(
            vector<Ciphertext> &batch_powers,
            SenderSessionContext &session_context,
            const WindowingDag &dag,
            WindowingDag::State &state,
            MemoryPoolHandle pool
        ) {
            if (batch_powers.size() != params_.split_size() + 1)
            {
                std::cout << batch_powers.size() << " != " << params_.split_size() + 1 << std::endl;
                throw std::runtime_error("");
            }

            size_t idx = static_cast<size_t>((*state.next_node)++);
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
            for (size_t i = 0; i < state.nodes.size(); ++i)
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

        uint64_t WindowingDag::pow(uint64_t base, uint64_t e)
        {
            uint64_t r = 1;
            while (e--)
                r *= base;
            return r;
        }

        size_t WindowingDag::optimal_split(size_t x, vector<uint32_t> &degrees)
        {
            uint32_t opt_deg = degrees[x];
            size_t opt_split = 0;

            auto abs_sub = [](uint32_t a, uint32_t b) {
                return abs(static_cast<int32_t>(a) - static_cast<int32_t>(b));
            };

            for (size_t i1 = 1; i1 < x; i1++)
            {
                if (degrees[i1] + degrees[x - i1] < opt_deg)
                {
                    opt_split = i1;
                    opt_deg = degrees[i1] + degrees[x - i1];
                }
                else if (
                    degrees[i1] + degrees[x - i1] == opt_deg &&
                    abs_sub(degrees[i1], degrees[x - i1]) < abs_sub(degrees[opt_split], degrees[x - opt_split]))
                {
                    opt_split = i1;
                }
            }

            degrees[x] = opt_deg;

            return opt_split;
        }

        vector<uint64_t> WindowingDag::conversion_to_digits(uint64_t input, uint32_t base)
        {
            vector<uint64_t> result;
            while (input > 0)
            {
                result.push_back(input % base);
                input /= base;
            }
            return result;
        }

        void WindowingDag::compute_dag()
        {
            vector<uint32_t> degree(max_power + 1, numeric_limits<uint32_t>::max());
            vector<size_t> splits(max_power + 1);
            vector<int> items_per(max_power, 0);

            Log::debug("Computing windowing dag: max power = %i", max_power);

            // initialize the degree array.
            degree[0] = 0;
            uint32_t base = uint32_t(1) << window;
            for (uint32_t i = 0; i < given_digits; i++)
            {
                for (uint32_t j = 1; j < base; j++)
                {
                    if (pow(base, i) * j < degree.size())
                    {
                        degree[static_cast<size_t>(pow(base, i) * j)] = 1;
                    }
                }
            }

            for (size_t i = 1; i <= max_power; i++)
            {
                size_t i1 = optimal_split(i, degree);
                size_t i2 = util::sub_safe(i, i1);
                splits[i] = i1;

                if (i1 == 0 || i2 == 0)
                {
                    base_powers.emplace_back(i);
                    degree[i] = 1;
                }
                else
                {
                    degree[i] = degree[i1] + degree[i2];
                    ++items_per[static_cast<size_t>(degree[i])];
                }
                Log::debug("degree[%i] = %i", i, degree[i]);
                Log::debug("splits[%i] = %i", i, splits[i]);
            }

            for (size_t i = 3; i < max_power && items_per[i]; i++)
            {
                items_per[i] += items_per[i - 1];
            }

            for (size_t i = 0; i < max_power; i++)
            {
                Log::debug("items_per[%i] = %i", i, items_per[i]);
            }

            // size = how many powers we still need to generate.
            size_t size = max_power - base_powers.size();
            nodes.resize(size);

            for (size_t i = 1; i <= max_power; i++)
            {
                size_t i1 = splits[i];
                size_t i2 = util::sub_safe(i, i1);

                if (i1 && i2) // if encryption(y^i) is not given
                {
                    auto idx = static_cast<size_t>(items_per[static_cast<size_t>(degree[i]) - 1]++);
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
            next_node = make_unique<std::atomic<size_t>>();
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
