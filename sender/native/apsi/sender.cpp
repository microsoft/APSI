// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <chrono>
#include <numeric>
#include <thread>

// APSI
#include "apsi/psiparams.h"
#include "apsi/logging/log.h"
#include "apsi/network/result_package.h"
#include "apsi/sender.h"
#include "apsi/util/utils.h"
#include "apsi/cryptocontext.h"
#include "apsi/sealobject.h"

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

        void Sender::query(RelinKeys relin_keys, map<uint64_t, vector<SEALObject<Ciphertext>>> query,
            vector<SEAL_BYTE> client_id, Channel &channel)
        {
            // Acquire read locks on SenderDB and Sender
            auto sender_lock = get_reader_lock();
            auto sender_db_lock = sender_db_->get_reader_lock();

            // Check that the database is set
            if (!sender_db_)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stop_watch, "Sender::query");
            Log::info("Start processing query");

            // Create the session context; we don't have to re-create the SEALContext every time
            CryptoContext crypto_context(seal_context_);
            crypto_context.set_evaluator(move(relin_keys));

            uint32_t bundle_idx_count = params_.bundle_idx_count();
            uint32_t max_items_per_bin = params_.table_params().max_items_per_bin;

            /* Receive client's query data. */
            int num_of_powers = static_cast<int>(query.size());
            Log::debug("Number of powers: %i", num_of_powers);
            Log::debug("Current bundle index count: %i", bundle_idx_count);

            // The number of powers necessary to compute PSI is equal to the largest number of elements inside any bin
            // under this bundle index. Globally, this is at most max_items_per_bin.
            size_t max_exponent = max_items_per_bin;

            // For each bundle index i, we need a vector of powers of the query Qᵢ. We need powers all
            // the way up to Qᵢ^max_items_per_bin (maybe less if the BinBundles aren't as full as expected). We don't
            // store the zeroth power.
            vector<CiphertextPowers> all_powers(bundle_idx_count);

            // Initialize powers
            for (CiphertextPowers &powers : all_powers)
            {
                powers.reserve(max_exponent);
            }

            // Load inputs provided in the query. These are the precomputed powers we will use for windowing.
            for (auto &q : query)
            {
                // The exponent of all the query powers we're about to iterate through
                size_t exponent = static_cast<size_t>(q.first);

                // Load Qᵢᵉ for all bundle indices i, where e is the exponent specified above
                for (size_t bundle_idx = 0; bundle_idx < all_powers.size(); bundle_idx++)
                {
                    // Load input^power to all_powers[bundle_idx][exponent-1]. The -1 is because we don't store
                    // the zeroth exponent
                    all_powers[bundle_idx][exponent - 1] = move(q.second[bundle_idx].extract_local());
                }
            }

            // Obtain the windowing information
            uint32_t window_size = params_.table_params().window_size;
            uint32_t base = uint32_t(1) << window_size;

            // Ceiling of num_of_powers / (base - 1)
            uint32_t given_digits = (static_cast<uint32_t>(num_of_powers) + base - 2) / (base - 1);

            // Prepare the windowing information
            WindowingDag dag(max_exponent, window_size, given_digits);

            // Create a state per each bundle index; this contains information about whether the
            // powers for that bundle index have been computed
            std::vector<WindowingDag::State> states;
            states.reserve(bundle_idx_count);
            for (uint32_t i = 0; i < bundle_idx_count; i++)
            {
                states.emplace_back(dag);
            }

            // Partition the data and run the threads on the partitions. The i-th thread will compute query powers at
            // bundle indices starting at partitions[i], up to but not including partitions[i+1].
            auto partitions = partition_evenly(bundle_idx_count, safe_cast<uint32_t>(thread_count_));

            // Launch threads, but not more than necessary
            vector<thread> threads;
            for (size_t t = 0; t < partitions.size(); t++)
            {
                threads.emplace_back([&, t]() {
                    query_worker(
                        partitions[t], all_powers,
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
            vector<CiphertextPowers> &all_powers,
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
                CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
                compute_powers(powers_at_this_bundle_idx, crypto_context, dag, states[bundle_idx]);

                // Next, iterate over each bundle with this bundle index
                auto bundle_caches = sender_db_->get_cache(bundle_idx).size();
                size_t bundle_count = bundle_caches.size();

                // When using C++17 this function may be multi-threaded in the future
                // with C++ execution policies
                seal_for_each_n(bundle_caches.begin(), bundle_count, [&](auto &cache) {
                    // Package for the result data
                    ResultPackage pkg;

                    pkg.client_id = client_id;
                    pkg.bundle_idx = bundle_idx;

                    // Compute the matching result and move to pkg
                    pkg.psi_result = move(cache.batched_matching_polyn.eval(all_powers[bundle_idx]));

                    if (cache.batched_interp_polyn)
                    {
                        // Compute the label result and move to pkg
                        pkg.label_result.emplace_back(cache.batched_interp_polyn.eval(all_powers[bundle_idx]));
                    }

                    // Start sending on the channel
                    channel.send(pkg);
                });
            }
        }

        /**
        Fills out the list of ciphertext powers, give some precomputed powers and a DAG describing how to construct the
        rest of the powers
        */
        void Sender::compute_powers(
            CiphertextPowers &powers,
            CryptoContext &crypto_context,
            const WindowingDag &dag,
            WindowingDag::State &state
        ) {
            // The number of powers necessary to compute PSI is equal to the largest number of elements inside any bin
            // under this bundle index. Globally, this is at most max_items_per_bin.
            uint32_t max_exponent = params_.table_params().max_items_per_bin;
            uint32_t bundle_idx_count = params_.bundle_idx_count();

            if (powers.size() != max_exponent)
            {
                throw std::runtime_error("Need room to compute max_exponent many ciphertext powers");
            }

            Evaluator &evaluator = crypto_context.evaluator();

            // Traverse each node of the DAG, building up products. That is, we calculate node.input[0]*node.input[1].
            // I know infinilooping is a bad pattern but the condition we're looping on is an atomic fetch_add, which
            // makese things harder. The top of this loop handles the break condition.
            while (true)
            {
                // Atomically get the next_node counter (this tells us where to start working) and increment it
                size_t node_idx = static_cast<size_t>(state.next_node.fetch_add(1));
                // If we've traversed the whole DAG, we're done
                if (node_idx >= dag.nodes.size())
                {
                    break;
                }

                auto &node = dag.nodes[node_idx];
                auto &node_state = state.nodes[node.output];

                // Atomically transition this node from Ready to Pending. This makes sure we're the only one who's
                // writing to it. The _strong specifier here means that this doesn't fail spuriously, i.e., if the
                // return value is false, it means that the comparison failed and someone else has begun working on this
                // node. If this happens, just move along to the next node.
                bool r = node_state.compare_exchange_strong(
                    WindowingDag::NodeState::Ready,
                    WindowingDag::NodeState::Pending
                );
                if (!r)
                {
                    continue;
                }

                // We need to multiply the two input nodes. Wait for them to be computed (their values might depend on
                // values lower on the DAG)
                for (size_t i = 0; i < 2; i++)
                {
                    // Loop until the input is computed
                    while (state.nodes[node.inputs[i]] != WindowingDag::NodeState::Done) {}
                }

                // Multiply the inputs together
                Ciphertext &input0 = powers[node.inputs[0]];
                Ciphertext &input1 = powers[node.inputs[1]];
                Ciphertext &output = powers[node.output];
                evaluator.multiply(input0, input1, output);

                // Relinearize and convert to NTT form
                evaluator.relinearize_inplace(output, crypto_context.relin_keys_);
                evaluator.transform_to_ntt_inplace(powers[i]);

                // Atomically transition this node from Pending to Done. Since we already "claimed" this node by marking
                // it Pending, this MUST still be Pending. If it's not, someone stole our work against our wishes. This
                // should never happen.
                bool r = node_state.compare_exchange_strong(
                    WindowingDag::NodeState::Pending,
                    WindowingDag::NodeState::Done
                );
                if (!r)
                {
                    throw std::runtime_error("FATAL: A node's work was stolen from it. This should never happen.");
                }
            }
        }

        /**
        Computes base^exp. Does not check for overflow
        */
        uint64_t WindowingDag::pow(uint64_t base, uint64_t exp)
        {
            uint64_t r = 1;
            while (exp > 0)
            {
                r *= base;
                exp--;
            }
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

        void WindowingDag::compute_dag()
        {
            vector<uint32_t> degrees(max_power + 1, numeric_limits<uint32_t>::max());
            vector<size_t> splits(max_power + 1);
            vector<int> items_per(max_power, 0);

            Log::debug("Computing windowing dag: max power = %i", max_power);

            // initialize the degrees array.
            degrees[0] = 0;
            uint32_t base = uint32_t(1) << window;
            for (uint32_t i = 0; i < given_digits; i++)
            {
                for (uint32_t j = 1; j < base; j++)
                {
                    if (pow(base, i) * j < degrees.size())
                    {
                        degrees[static_cast<size_t>(pow(base, i) * j)] = 1;
                    }
                }
            }

            for (size_t i = 1; i <= max_power; i++)
            {
                size_t i1 = optimal_split(i, degrees);
                size_t i2 = util::sub_safe(i, i1);
                splits[i] = i1;

                if (i1 == 0 || i2 == 0)
                {
                    base_powers.emplace_back(i);
                    degrees[i] = 1;
                }
                else
                {
                    degrees[i] = degrees[i1] + degrees[i2];
                    ++items_per[static_cast<size_t>(degrees[i])];
                }
                Log::debug("degrees[%i] = %i", i, degrees[i]);
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
                    auto idx = static_cast<size_t>(items_per[static_cast<size_t>(degrees[i]) - 1]++);
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
