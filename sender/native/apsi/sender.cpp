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
#include "seal/valcheck.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
    using namespace logging;
    using namespace util;
    using namespace oprf;
    using namespace network;

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

        QueryRequest::QueryRequest(unique_ptr<SenderOperation> sop, shared_ptr<SenderDB> sender_db)
        {
            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::SOP_QUERY)
            {
                throw invalid_argument("operation is not a query request");
            }
            if (!sender_db)
            {
                throw invalid_argument("sender_db cannot be null");
            }

            // Move over the SenderDB
            sender_db_ = move(sender_db);

            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop.get());

            // Extract and validate relinearization keys 
            relin_keys_ = sop_query->relin_keys.extract_local();
            if (!is_valid_for(relin_keys_, sender_db_->get_context().seal_context()))
            {
                throw invalid_argument("relinearization keys are invalid");
            }

            // Extract and validate query ciphertexts
            for (auto &q : sop_query->data)
            {
                vector<Ciphertext> cts;
                for (auto &ct : q.second)
                {
                    cts.push_back(ct.extract_local());
                    if (!is_valid_for(cts.back(), sender_db_->get_context().seal_context()))
                    {
                        throw invalid_argument("query ciphertext is invalid");
                    }
                }
                data_[q.first] = move(cts);
            }

            // Extract the PowersDag
            pd_ = move(sop_query->pd);

            // Get the PSIParams
            PSIParams params(sender_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t query_powers_count = params.query_params().query_powers_count;

            // Check that the PowersDag is valid and matches the PSIParams
            if (!pd_.is_configured() ||
                pd_.up_to_power() != max_items_per_bin ||
                pd_.source_count() != query_powers_count)
            {
                throw invalid_argument("PowersDag is invalid");
            }

            // Check that the query data size matches the PSIParams
            if (data_.size() != query_powers_count)
            {
                throw invalid_argument("number of ciphertext powers does not match the parameters");
            }
            auto query_powers = pd_.source_nodes();
            for (auto &q : data_)
            {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count)
                {
                    throw invalid_argument("number of ciphertexts does not match the parameters");
                }
                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) { return n.power == q.first; });
                if (where == query_powers.cend())
                {
                    throw invalid_argument("query ciphertext data does not match the PowersDag");
                }
            }
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
            network::Channel &chl,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun)
        {
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
            Channel &chl,
            size_t thread_count,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            STOPWATCH(sender_stopwatch, "Sender::RunQuery");
            APSI_LOG_INFO("Start processing query request");

            auto sender_db = move(query_request.sender_db_);

            // Acquire read lock on SenderDB
            auto sender_db_lock = sender_db->get_reader_lock();

            // Copy over the CryptoContext from SenderDB; set the Evaluator for this local instance
            CryptoContext crypto_context(sender_db->get_context());
            crypto_context.set_evaluator(move(query_request.relin_keys_));

            // Get the PSIParams
            PSIParams params(sender_db->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t query_powers_count = params.query_params().query_powers_count;

            // Extract the PowersDag
            PowersDag pd = move(query_request.pd_);

            // The query response only tells how many ResultPackages to expect; send this first
            uint32_t package_count = safe_cast<uint32_t>(sender_db->bin_bundle_count());
            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            send_fun(chl, move(response_query));

            // For each bundle index i, we need a vector of powers of the query Qᵢ. We need powers all
            // the way up to Qᵢ^max_items_per_bin (maybe less if the BinBundles aren't as full as expected). We don't
            // store the zeroth power.
            vector<CiphertextPowers> all_powers(bundle_idx_count);

            // Initialize powers
            for (CiphertextPowers &powers : all_powers)
            {
                // The + 1 is because we index by power. The 0th power is a dummy value. I promise this makes things
                // easier to read.
                powers.resize(max_items_per_bin + 1);
            }

            // Load inputs provided in the query
            for (auto &q : query_request.data_)
            {
                // The exponent of all the query powers we're about to iterate through
                size_t exponent = static_cast<size_t>(q.first);

                // Load Qᵢᵉ for all bundle indices i, where e is the exponent specified above
                for (size_t bundle_idx = 0; bundle_idx < all_powers.size(); bundle_idx++)
                {
                    // Load input^power to all_powers[bundle_idx][exponent]
                    all_powers[bundle_idx][exponent] = move(q.second[bundle_idx]);
                }
            }

            // Partition the data and run the threads on the partitions. The i-th thread will compute query powers at
            // bundle indices starting at partitions[i], up to but not including partitions[i+1].
            auto partitions = partition_evenly(bundle_idx_count, safe_cast<uint32_t>(thread_count));

            // Launch threads, but not more than necessary
            vector<thread> threads;
            for (size_t t = 0; t < partitions.size(); t++)
            {
                threads.emplace_back([&, t]() {
                    QueryWorker(sender_db, crypto_context, partitions[t], all_powers, pd, chl, send_rp_fun);
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
            CryptoContext crypto_context,
            pair<uint32_t, uint32_t> bundle_idx_bounds,
            vector<CiphertextPowers> &all_powers,
            const PowersDag &pd,
            Channel &chl,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            STOPWATCH(sender_stopwatch, "Sender::RunQuery::QueryWorker");

            uint32_t bundle_idx_start = bundle_idx_bounds.first;
            uint32_t bundle_idx_end = bundle_idx_bounds.second;

            // Compute the powers for each bundle index and loop over the BinBundles
            Evaluator &evaluator = *crypto_context.evaluator();
            RelinKeys &relin_keys = *crypto_context.relin_keys();
            for (uint32_t bundle_idx = bundle_idx_start; bundle_idx < bundle_idx_end; bundle_idx++)
            {
                // Compute all powers of the query
                CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
                pd.apply([&](const PowersDag::PowersNode &node) {
                    if (!node.is_source())
                    {
                        auto parents = node.parents;
                        Ciphertext prod;
                        evaluator.multiply(
                            powers_at_this_bundle_idx[parents.first],
                            powers_at_this_bundle_idx[parents.second],
                            prod);
                        evaluator.relinearize_inplace(prod, relin_keys);
                        powers_at_this_bundle_idx[node.power] = move(prod);
                    }
                });

                // Transform the powers to NTT form
                // When using C++17 this function may be multi-threaded in the future
                // with C++ execution policies
                seal_for_each_n(powers_at_this_bundle_idx.begin() + 1, powers_at_this_bundle_idx.size() - 1, [&](auto &ct) {
                    evaluator.transform_to_ntt_inplace(ct);
                });

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
    } // namespace sender
} // namespace apsi
