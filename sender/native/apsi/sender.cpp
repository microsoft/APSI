// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cmath>
#include <chrono>
#include <numeric>
#include <thread>
#include <future>

// APSI
#include "apsi/sender.h"
#include "apsi/psiparams.h"
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/sealobject.h"
#include "apsi/logging/log.h"
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
    using namespace oprf;
    using namespace network;

    namespace
    {
        /**
        Returns the Hamming weight of x in the given base, i.e., the number of nonzero digits x has in the given base.
        The base MUST be a power of 2
        */
        size_t hamming_weight(size_t x, uint32_t base)
        {
            // This mask is used to get each digits of x in the given base
            size_t base_bitmask = static_cast<size_t>(base - 1);
            size_t base_bitlen = static_cast<size_t>(log2(base));

            size_t weight = 0;

            // Go through all the digits by shifting the bitmask further to the left. Once the bitmask has gone all the
            // way off the edge, we stop.
            while (base_bitmask != 0)
            {
                // Mask x and see if the current digit is zero
                bool is_digit_nonzero = (base_bitmask & x) != 0;
                weight += static_cast<size_t>(is_digit_nonzero);

                // Shift the bitmask up to the next digit
                base_bitmask <<= base_bitlen;
            }

            return weight;
        }

        /**
        Given a base and an integer x, returns p,q such that p + q == x, weight(p) + weight(q) = weight(x), and
        weight(p) is as close to weight(q) as possible. Weight is as defined in the hamming_weight() function. The base
        MUST be a power of 2.
        */
        pair<size_t, size_t> balanced_integer_partition(size_t x, uint32_t base)
        {
            size_t x_weight = hamming_weight(x, base);

            // Now we just need to find a partition p,q of x such that weight(p) + weight(q) = weight(x) and the two
            // weights on the LHS are close to each other. Our strategy, just keep picking digits from x to include in
            // q. Once q has weight ⌊weight(x)/2⌋, let p := x - q and we're done.

            // This mask is used to get each digits of x in the given base
            size_t base_bitmask = static_cast<size_t>(base - 1);
            size_t base_bitlen = static_cast<size_t>(log2(base));

            // Loop until q is half the weight of x. Once this is the case, we have uniquely determined a partition.
            size_t q = 0;
            size_t q_weight = 0;
            while (q_weight < x_weight/2)
            {
                // Add a digit to q
                q |= (x & base_bitmask);

                // That digit might've been 0. If it wasn't, q's hamming weight just increase by 1
                bool is_digit_nonzero = (base_bitmask & x) != 0;
                q_weight += static_cast<size_t>(is_digit_nonzero);

                // Shift the bitmask up to the next digit
                base_bitmask <<= base_bitlen;
            }

            size_t p = x - q;
            return {p, q};
        }
    }

    namespace sender
    {
        ParmsRequest::ParmsRequest(unique_ptr<SenderOperation> sop)
        {
            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::SOP_PARMS)
            {
                throw invalid_argument("operation is not a parameter request");
            }
        }

        OPRFRequest::OPRFRequest(unique_ptr<SenderOperation> sop)
        {
            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::SOP_OPRF)
            {
                throw invalid_argument("operation is not an OPRF request");
            }

            auto sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop.get());
            data_ = move(sop_oprf->data);
        }

        QueryRequest::QueryRequest(unique_ptr<SenderOperation> sop)
        {
            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::SOP_QUERY)
            {
                throw invalid_argument("operation is not a query request");
            }

            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop.get());
            relin_keys_ = sop_query->relin_keys.extract_local();
            data_ = move(sop_query->data);
        }

        void Sender::RunParms(
            ParmsRequest &&parms_request,
            shared_ptr<SenderDB> sender_db,
            network::Channel &chl,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun)
        {
            // Check that the database is set
            if (!sender_db)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stopwatch, "Sender::RunParms");
            APSI_LOG_INFO("Start processing parameter request");

            auto response_parms = make_unique<SenderOperationResponseParms>();
            response_parms->params = make_unique<PSIParams>(sender_db->get_params());

            send_fun(chl, move(response_parms));
        }

        void Sender::RunOPRF(
            OPRFRequest &&oprf_request,
            const OPRFKey &key,
            shared_ptr<SenderDB> sender_db,
            network::Channel &chl,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun)
        {
            // Check that the database is set
            if (!sender_db)
            {
                throw logic_error("SenderDB is not set");
            }

            STOPWATCH(sender_stopwatch, "Sender::RunOPRF");
            APSI_LOG_INFO("Start processing OPRF request");

            // OPRF response has the same size as the OPRF query 
            vector<SEAL_BYTE> oprf_result(oprf_request.data_.size());
            OPRFSender::ProcessQueries(oprf_request.data_, key, oprf_result);

            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = move(oprf_result);

            send_fun(chl, move(response_oprf));
        }

        void Sender::RunQuery(
            QueryRequest &&query_request,
            shared_ptr<SenderDB> sender_db,
            Channel &chl,
            size_t thread_count,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            // Check that the database is set
            if (!sender_db)
            {
                throw logic_error("SenderDB is not set");
            }

            // Acquire read lock on SenderDB
            auto sender_db_lock = sender_db->get_reader_lock();

            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "Sender::RunQuery");
            APSI_LOG_INFO("Start processing query request");

            // The query response only tells how many ResultPackages to expect; send this first
            uint32_t package_count = safe_cast<uint32_t>(sender_db->bin_bundle_count());
            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            send_fun(chl, move(response_query));

            // Copy over the CryptoContext from SenderDB; set the Evaluator for this local instance
            CryptoContext crypto_context(sender_db->get_context());
            crypto_context.set_evaluator(move(query_request.relin_keys_));

            // Get the PSIParams
            PSIParams params(sender_db->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;

            /* Receive client's query data. */
            int num_of_powers = static_cast<int>(query_request.data_.size());
            APSI_LOG_DEBUG("Number of powers: " << num_of_powers);
            APSI_LOG_DEBUG("Current bundle index count: " << bundle_idx_count);

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
                powers.resize(max_exponent);
            }

            // Load inputs provided in the query. These are the precomputed powers we will use for windowing.
            for (auto &q : query_request.data_)
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
            uint32_t window_size = params.table_params().window_size;
            uint32_t base = uint32_t(1) << window_size;

            // Prepare the windowing information
            WindowingDag dag(max_exponent, base);

            // Create a state per each bundle index; this contains information about whether the
            // powers for that bundle index have been computed
            vector<WindowingDag::State> states;
            states.reserve(bundle_idx_count);
            for (uint32_t i = 0; i < bundle_idx_count; i++)
            {
                states.emplace_back(dag);
            }

            // Partition the data and run the threads on the partitions. The i-th thread will compute query powers at
            // bundle indices starting at partitions[i], up to but not including partitions[i+1].
            auto partitions = partition_evenly(bundle_idx_count, safe_cast<uint32_t>(thread_count));

            // Launch threads, but not more than necessary
            vector<thread> threads;
            for (size_t t = 0; t < partitions.size(); t++)
            {
                threads.emplace_back([&, t]() {
                    QueryWorker(sender_db, partitions[t], all_powers, dag, states, chl, send_rp_fun);
                });
            }

            // Wait for the threads to finish
            for (auto &t : threads)
            {
                t.join();
            }

            APSI_LOG_INFO("Finished processing query");
        }

        void Sender::QueryWorker(
            const shared_ptr<SenderDB> &sender_db,
            pair<uint32_t, uint32_t> bundle_idx_bounds,
            vector<CiphertextPowers> &all_powers,
            WindowingDag &dag,
            vector<WindowingDag::State> &states,
            Channel &chl,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            STOPWATCH(sender_stopwatch, "Sender::RunQuery::QueryWorker");

            uint32_t bundle_idx_start = bundle_idx_bounds.first;
            uint32_t bundle_idx_end = bundle_idx_bounds.second;

            // Compute the powers for each bundle index and loop over the BinBundles
            for (uint32_t bundle_idx = bundle_idx_start; bundle_idx < bundle_idx_end; bundle_idx++)
            {
                // Compute all powers of the query
                CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
                ComputePowers(
                    sender_db,
                    powers_at_this_bundle_idx,
                    dag,
                    states[bundle_idx]);

                // Next, iterate over each bundle with this bundle index
                auto bundle_caches = sender_db->get_cache_at(bundle_idx);
                size_t bundle_count = bundle_caches.size();

                // When using C++17 this function may be multi-threaded in the future
                // with C++ execution policies
                seal_for_each_n(bundle_caches.begin(), bundle_count, [&](auto &cache) {
                    // Package for the result data
                    auto rp = make_unique<ResultPackage>();

                    rp->bundle_idx = bundle_idx;

                    // Compute the matching result and move to rp
                    const BatchedPlaintextPolyn &matching_polyn = cache.get().batched_matching_polyn;
                    rp->psi_result = move(matching_polyn.eval(all_powers[bundle_idx]));

                    const BatchedPlaintextPolyn &interp_polyn = cache.get().batched_interp_polyn;
                    if (interp_polyn)
                    {
                        // Compute the label result and move to rp
                        rp->label_result.emplace_back(interp_polyn.eval(all_powers[bundle_idx]));
                    }

                    // Start sending on the channel 
                    send_rp_fun(chl, move(rp));
                });
            }
        }

        /**
        Fills out the list of ciphertext powers (C, C², C³, ...). The given powers vector may be uninitialized almost
        everywhere, but precomputed powers MUST be present at indices of the form x*base^y where base is the window size
        (the receiver is supposed to send these). The rest of the powers are constructed by multiplying existing powers.
        The goal is to minimize the circuit depth for these calculations, and so we use some precomputation to guide us.
        The WindowingDag is a directed acyclic graph, wherein each node has two incoming edges from nodes i₁, i₂ and an
        outgoing edge to node j = i₁ + i₂. A node tells us to construct Cʲ by multiplying Cⁱ¹ and Cⁱ². So this function
        just iterates through the DAG and multiplies the things it dictates until the powers vector is full.
        */
        void Sender::ComputePowers(
            const shared_ptr<SenderDB> &sender_db,
            CiphertextPowers &powers,
            const WindowingDag &dag,
            WindowingDag::State &state)
        {
            CryptoContext crypto_context(sender_db->get_context());
            const PSIParams &params(sender_db->get_params());

            // The number of powers necessary to compute PSI is equal to the largest number of elements inside any bin
            // under this bundle index. Globally, this is at most max_items_per_bin.
            uint32_t max_exponent = params.table_params().max_items_per_bin;
            uint32_t bundle_idx_count = params.bundle_idx_count();

            if (powers.size() != max_exponent)
            {
                throw runtime_error("Need room to compute max_exponent many ciphertext powers");
            }

            auto &evaluator = crypto_context.evaluator();
            auto &relin_keys = crypto_context.relin_keys();

            // Traverse each node of the DAG, building up products. That is, we calculate node.input[0]*node.input[1].
            // I know infinilooping is a bad pattern but the condition we're looping on is an atomic fetch_add, which
            // makes things harder. The top of this loop handles the break condition.
            while (true)
            {
                // Atomically get the next_node counter (this tells us where to start working) and increment it
                size_t node_idx = static_cast<size_t>(state.next_node->fetch_add(1));
                // If we've traversed the whole DAG, we're done
                if (node_idx >= dag.nodes_.size())
                {
                    break;
                }

                auto &node = dag.nodes_[node_idx];
                auto &output_node_state = state.node_states[node.output];

                // Atomically transition this node from Uncomputed to Computing. This makes sure we're the only one
                // who's writing to it. The _strong specifier here means that this doesn't fail spuriously, i.e., if the
                // return value is false, it means that the comparison failed and someone else has begun working on this
                // node. If this happens, just move along to the next node.
                auto uncomputed = WindowingDag::NodeState::Uncomputed;
                bool r = output_node_state.compare_exchange_strong(
                    uncomputed,
                    WindowingDag::NodeState::Computing
                );
                if (!r)
                {
                    continue;
                }

                // We need to multiply the two input nodes. Wait for them to be computed (their values might depend on
                // values lower on the DAG)
                for (size_t i = 0; i < 2; i++)
                {
                    // Spin until the input is computed
                    auto &input_node_state = state.node_states[node.inputs[i]];
                    while (input_node_state != WindowingDag::NodeState::Done) {}
                }

                // Multiply the inputs together
                Ciphertext &input0 = powers[node.inputs[0]];
                Ciphertext &input1 = powers[node.inputs[1]];
                Ciphertext &output = powers[node.output];
                evaluator->multiply(input0, input1, output);

                // Relinearize and convert to NTT form
                evaluator->relinearize_inplace(output, *relin_keys);
                evaluator->transform_to_ntt_inplace(output);

                // Atomically transition this node from Computing to Done. Since we already "claimed" this node by
                // marking it Computing, this MUST still be Computing. If it's not, someone stole our work against our
                // wishes. This should never happen.
                auto computing = WindowingDag::NodeState::Computing;
                bool s = output_node_state.compare_exchange_strong(
                    computing,
                    WindowingDag::NodeState::Done
                );
                if (!s)
                {
                    throw runtime_error("FATAL: A node's work was stolen from it. This should never happen.");
                }
            }
        }

        /**
        Constructs a directed acyclic graph, where each node has 2 inputs and 1 output. Every node has inputs i,j and
        output i+j. The largest power has exponent max_exponent. The choice of inputs depends on their Hamming weights,
        which depends on the base specified (the base is also known as the window size, and MUST be a power of 2). This
        is used to compute powers of a given ciphertext while minimizing circuit depth. The nodes vector is sorted in
        increasing order of Hamming weight of output.
        */
        WindowingDag::WindowingDag(size_t max_exponent, uint32_t base) : max_exponent_(max_exponent), base_(base)
        {
            for (size_t i = 1; i <= max_exponent; i++)
            {
                // Compute a balanced partition of the index i with respect to the given base
                pair<size_t, size_t> partition = balanced_integer_partition(i, base);
                size_t i1 = partition.first;
                size_t i2 = partition.second;

                // You only have to compute a ciphertext power if the power isn't already given, i.e., iff i isn't of
                // the form x*base^y (for x < base), i.e., iff i isn't just 1 digit wrt the base, i.e., iff i has a
                // nontrivial partition
                if (i1 && i2)
                {
                    Node node { { i1, i2 }, i, };
                    nodes_.emplace_back(node);
                }
            }

            // Sort the DAG in increasing order by Hamming weight of their output
            sort(nodes_.begin(), nodes_.end(), [base](const Node &node1, const Node &node2) -> bool {
                return hamming_weight(node1.output, base) < hamming_weight(node2.output, base);
            });

            // Result of computation is now in nodes_
        }

        /**
        Constructs the working state of a DAG. This includes the index to the next yet-to-be-computed node
        */
        WindowingDag::State::State(WindowingDag &dag)
        {
            // Workers start at the beginning of the nodes_ array, since that's where the lowest-weight nodes are
            next_node = make_unique<atomic<size_t>>();
            *next_node = 0;

            // Everything (except the given powers) is uncomputed at first
            size_t max_exponent = dag.max_exponent_;
            node_states.reset(new atomic<NodeState>[max_exponent]);
            for (size_t i = 0; i < max_exponent; i++)
            {
                node_states[i].store(NodeState::Uncomputed);
            }

            // Mark the given powers as computed (since they were precomputed by receiver). These are the powers of the
            // form C^r where r is x*base^y and 1 <= x < base.
            size_t x = 1;
            size_t y = 0;
            size_t given_power;
            size_t base = dag.base_;
            size_t base_bitlen = static_cast<size_t>(log2(base));
            while (given_power < max_exponent)
            {
                // The given power has exponent x*base^y, where base is a power of 2
                given_power = x * (base << (base_bitlen * y));

                // Set the given power to "computed"
                node_states[given_power].store(NodeState::Done);

                // Get the next (x,y). Remember 1 <= x < base. To get in that range, we take it mod (base-1) and add 1.
                x = (x % (base - 1)) + 1;
                // If x wrapped back around to 1, increment the power
                if (x == 1) {
                    y++;
                }
            }
        }
    } // namespace sender
} // namespace apsi
