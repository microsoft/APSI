// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <chrono>
#include <numeric>
#include <thread>

// APSI
#include "apsi/psiparams.h"
#include "apsi/logging/log.h"
#include "apsi/network/network_utils.h"
#include "apsi/network/result_package.h"
#include "apsi/sender.h"
#include "apsi/util/utils.h"
#include "apsi/cryptocontext.h"

// SEAL
#include "seal/modulus.h"
#include "seal/util/common.h"
#include "seal/util/iterator.h"
#include "seal/evaluator.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    using namespace logging;
    using namespace util;
    using namespace network;

    namespace sender
    {
        Sender::Sender(const PSIParams &params, size_t thread_count)
            : params_(params), thread_count_(thread_count),
              seal_context_(SEALContext::Create(params_.seal_params()))
        {
            if (thread_count < 1)
            {
                throw invalid_argument("thread_count must be at least 1");
            }
        }

        void Sender::query(
            const string &relin_keys, const map<uint64_t, vector<string>> &query, const vector<SEAL_BYTE> &client_id,
            Channel &channel)
        {
            // Acquire a read lock on the database
            auto lock = sender_db_lock_.acquire_read();

            // Check that the database is set
            if (!sender_db_)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stop_watch, "Sender::query");
            Log::info("Start processing query");

            // Create the session context; we don't have to re-create the SEALContext every time
            CryptoContext crypto_context(seal_context_);
            crypto_context.set_evaluator(relin_keys);

            uint32_t bundle_idx_count = params_.bundle_idx_count();
            uint32_t split_size = params_.table_params().split_size;

            /* Receive client's query data. */
            int num_of_powers = static_cast<int>(query.size());
            Log::debug("Number of powers: %i", num_of_powers);
            Log::debug("Current bundle index count: %i", bundle_idx_count);

            // For each bundle index, we have a vector of powers of the query. We need powers all
            // the way to split_size; however, we don't store the zeroth power.
            vector<vector<Ciphertext>> powers(bundle_idx_count);

            // Initialize the powers matrix
            for (size_t i = 0; i < powers.size(); i++)
            {
                powers[i].reserve(split_size);
                for (uint32_t j = 0; j < split_size; j++)
                {
                    powers[i].emplace_back(seal_context_);
                }
            }

            // Load inputs provided in the query
            for (const auto &q : query)
            {
                size_t power = static_cast<size_t>(q.first);
                for (size_t bundle_idx = 0; bundle_idx < powers.size(); bundle_idx++)
                {
                    // Load input^power to powers[bundle_idx][power-1]
                    from_string(seal_context_, q.second[bundle_idx], powers[bundle_idx][power - 1]);
                }
            }

            // Obtain the windowing information
            uint32_t window_size = params_.table_params().window_size;
            uint32_t base = uint32_t(1) << window_size;

            // Ceiling of num_of_powers / (base - 1)
            uint32_t given_digits = (static_cast<uint32_t>(num_of_powers) + base - 2) / (base - 1);

            // Prepare the windowing information
            WindowingDag dag(split_size, window_size, given_digits);

            // Create a state per each bundle index; this contains information about whether the
            // powers for that bundle index have been computed
            std::vector<WindowingDag::State> states;
            states.reserve(bundle_idx_count);
            for (uint32_t i = 0; i < bundle_idx_count; i++)
            {
                states.emplace_back(dag);
            }

            // Partition the data and run the threads on the partitions. The i-th thread will process
            // bundle indices partitions[i] up to but not including partitions[i+1].
            auto partitions = partition_evenly(bundle_idx_count, safe_cast<uint32_t>(thread_count_));

            // Launch threads, but not more than necessary
            vector<thread> threads;
            for (size_t t = 0; t < partitions.size(); t++)
            {
                threads.emplace_back([&, t]() {
                    query_worker(
                        partitions[t], powers,
                        crypto_context, dag, states, client_id, channel);
                });
            }

            // Wait for the threads to finish
            for (auto &t : threads)
            {
                t.join();
            }

            Log::info("Finished processing query");
        }

        void Sender::query_worker(
            pair<uint32_t, uint32_t> bundle_idx_bounds,
            vector<vector<Ciphertext>> &powers,
            const CryptoContext &crypto_context,
            WindowingDag &dag,
            vector<WindowingDag::State> &states,
            const vector<SEAL_BYTE> &client_id,
            Channel &channel)
        {
            STOPWATCH(sender_stop_watch, "Sender::query_worker");

            uint32_t bundle_idx_start = bundle_idx_bounds.first;
            uint32_t bundle_idx_end = bundle_idx_bounds.second;

            // Compute the powers for each bundle index and loop over the BinBundles
            for (uint32_t bundle_idx = bundle_idx_start; bundle_idx < bundle_idx_end; bundle_idx++)
            {
                // Compute all powers of the query
                compute_batch_powers(powers[bundle_idx], crypto_context, dag, states[bundle_idx]);

                // Lock the database from modifications
                auto lock = sender_db_->get_reader_lock();

                // Next, iterate over each bundle with this bundle index
                auto bundle_caches = sender_db_->get_cache(bundle_idx).size();
                size_t bundle_count = bundle_caches.size();

                // When using C++17 this function may be multi-threaded in the future
                // with C++ execution policies
                seal_for_each_n(bundle_caches.begin(), bundle_count, [&](auto &cache) {
                    // Package for the result data
                    ResultPackage pkg;
                    pkg.bundle_idx = bundle_idx;

                    // Compute the matching result, convert to a string, and write to pkg
                    pkg.data = to_string(cache.batched_matching_polyn.eval(powers[bundle_idx]));

                    if (cache.batched_interp_polyn)
                    {
                        // Compute the label result, convert to a string, and write to pkg
                        pkg.label_data = to_string(cache.batched_interp_polyn.eval(powers[bundle_idx]));
                    }

                    // Start sending on the channel
                    channel.send(client_id, pkg);
                });
            }
        }

        void Sender::compute_batch_powers(
            vector<Ciphertext> &batch_powers,
            CryptoContext &crypto_context,
            const WindowingDag &dag,
            WindowingDag::State &state)
        {
            uint32_t bundle_idx_count = params_.bundle_idx_count();
            uint32_t split_size = params_.table_params().split_size;

            if (batch_powers.size() != split_size + 1)
            {
                std::cout << batch_powers.size() << " != " << split_size + 1 << std::endl;
                throw std::runtime_error("");
            }

            size_t idx = static_cast<size_t>((*state.next_node)++);
            Evaluator &evaluator = *crypto_context.evaluator();
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
                    batch_powers[node.inputs[0]], batch_powers[node.inputs[1]], batch_powers[node.output]);
                evaluator.relinearize_inplace(batch_powers[node.output], crypto_context.relin_keys_);

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
