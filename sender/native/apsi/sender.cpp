// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cmath>
#include <chrono>
#include <numeric>
#include <thread>
#include <future>
#include <sstream>

// APSI
#include "apsi/sender.h"
#include "apsi/psi_params.h"
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/seal_object.h"
#include "apsi/logging/log.h"
#include "apsi/util/utils.h"
#include "apsi/crypto_context.h"
#include "apsi/util/stopwatch.h"

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
            STOPWATCH(sender_stopwatch, "ParmsRequest::ParmsRequest");

            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::sop_parms)
            {
                throw invalid_argument("operation is not a parameter request");
            }
        }

        OPRFRequest::OPRFRequest(unique_ptr<SenderOperation> sop)
        {
            STOPWATCH(sender_stopwatch, "OPRFRequest::OPRFRequest");

            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::sop_oprf)
            {
                throw invalid_argument("operation is not an OPRF request");
            }

            auto sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop.get());
            data_ = move(sop_oprf->data);
        }

        QueryRequest::QueryRequest(unique_ptr<SenderOperation> sop, shared_ptr<SenderDB> sender_db)
        {
            STOPWATCH(sender_stopwatch, "QueryRequest::QueryRequest");

            if (!sop)
            {
                throw invalid_argument("operation cannot be null");
            }
            if (sop->type() != SenderOperationType::sop_query)
            {
                throw invalid_argument("operation is not a query request");
            }
            if (!sender_db)
            {
                throw invalid_argument("sender_db cannot be null");
            }

            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop.get());

            // Move over the SenderDB
            sender_db_ = move(sender_db);
            auto seal_context = sender_db_->get_context().seal_context();

            // Extract and validate relinearization keys 
            relin_keys_ = sop_query->relin_keys.extract_local();
            if (!is_valid_for(relin_keys_, *seal_context))
            {
                APSI_LOG_ERROR("Extracted relinearization keys are invalid for SEALContext");
                throw invalid_argument("relinearization keys are invalid");
            }

            // Extract and validate query ciphertexts
            for (auto &q : sop_query->data)
            {
                APSI_LOG_DEBUG("Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                vector<Ciphertext> cts;
                for (auto &ct : q.second)
                {
                    cts.push_back(ct.extract_local());
                    if (!is_valid_for(cts.back(), *seal_context))
                    {
                        APSI_LOG_ERROR("Extracted ciphertext is invalid for SEALContext");
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
            if (!pd_.is_configured())
            {
                APSI_LOG_ERROR("Extracted PowersDag is not configured");
                throw invalid_argument("PowersDag is not configured");
            }
            if (pd_.up_to_power() != max_items_per_bin)
            {
                APSI_LOG_ERROR("Extracted PowersDag is incompatible with PSI parameters: "
                    "up_to_power (" << pd_.up_to_power() << ") does not match max_items_per_bin (" <<
                    max_items_per_bin << ")");
                throw invalid_argument("PowersDag is incompatible with PSI parameters");
            }
            if (pd_.source_count() != query_powers_count)
            {
                APSI_LOG_ERROR("Extracted PowersDag is incompatible with PSI parameters: "
                    "source_count (" << pd_.source_count() << ") does not match query_power_count (" <<
                    query_powers_count << ")");
                throw invalid_argument("PowersDag is incompatible with PSI parameters");
            }

            // Check that the query data size matches the PSIParams
            if (data_.size() != query_powers_count)
            {
                APSI_LOG_ERROR("Extracted query data is incompatible with PSI parameters: "
                    "query contains " << data_.size() << " ciphertext powers which does not match with "
                    "query_power_count (" << query_powers_count << ")");
                throw invalid_argument("number of ciphertext powers is incompatible with PSI parameters");
            }
            auto query_powers = pd_.source_nodes();
            for (auto &q : data_)
            {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count)
                {
                    APSI_LOG_ERROR("Extracted query data is incompatible with PSI parameters: "
                        "query power " << q.first << " contains " << q.second.size() << " ciphertexts which does not "
                        "match with bundle_idx_count (" << bundle_idx_count << ")");
                    throw invalid_argument("number of ciphertexts is incompatible with PSI parameters");
                }
                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) { return n.power == q.first; });
                if (where == query_powers.cend())
                {
                    APSI_LOG_ERROR("Extracted query data is incompatible with PowersDag: "
                        "query power " << q.first << " does not match with a source node in PowersDag");
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

            APSI_LOG_INFO("Sending parameter request response: " << response_parms->params->to_string());
            send_fun(chl, move(response_parms));
            APSI_LOG_INFO("Finished processing parameter request");
        }

        void Sender::RunOPRF(
            OPRFRequest &&oprf_request,
            const OPRFKey &key,
            network::Channel &chl,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun)
        {
            STOPWATCH(sender_stopwatch, "Sender::RunOPRF");
            APSI_LOG_INFO("Start processing OPRF request for "
                << oprf_request.data_.size() / oprf_query_size << " items");

            // OPRF response has the same size as the OPRF query 
            vector<seal_byte> oprf_result;
            try
            {
                oprf_result = OPRFSender::ProcessQueries(oprf_request.data_, key);
            }
            catch (const exception &ex)
            {
                // Something was wrong with the OPRF request. This can mean malicious
                // data being sent to the sender in an attempt to extract OPRF key.
                // Best not to respond anything.
                APSI_LOG_ERROR("Processing OPRF request threw an exception: " << ex.what());
                return;
            }

            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = move(oprf_result);

            APSI_LOG_INFO("Sending OPRF request response");
            send_fun(chl, move(response_oprf));
            APSI_LOG_INFO("Finished processing OPRF request");
        }

        void Sender::RunQuery(
            QueryRequest &&query_request,
            Channel &chl,
            size_t thread_count,
            function<void(Channel &, unique_ptr<SenderOperationResponse>)> send_fun,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            thread_count = thread_count < 1 ? thread::hardware_concurrency() : thread_count;

            auto sender_db = move(query_request.sender_db_);

            // Acquire read lock on SenderDB
            auto sender_db_lock = sender_db->get_reader_lock();

            STOPWATCH(sender_stopwatch, "Sender::RunQuery");
            APSI_LOG_INFO("Start processing query request on database with "
                << sender_db->get_items().size() << " items");

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
            uint32_t package_count = safe_cast<uint32_t>(sender_db->get_bin_bundle_count());
            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            APSI_LOG_INFO("Sending query request response: expect " << package_count << " packages");
            send_fun(chl, move(response_query));
            APSI_LOG_INFO("Query request response sent");

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
                    APSI_LOG_DEBUG("Extracting query ciphertext power " << exponent
                        << " for bundle index " << bundle_idx);
                    all_powers[bundle_idx][exponent] = move(q.second[bundle_idx]);
                }
            }

            // Partition the data and run the threads on the partitions. The i-th thread will compute query powers at
            // bundle indices starting at partitions[i], up to but not including partitions[i+1].
            auto partitions = partition_evenly(bundle_idx_count, safe_cast<uint32_t>(thread_count));

            // Launch threads, but not more than necessary
            vector<thread> threads;
            APSI_LOG_INFO("Launching " << partitions.size() << " query worker threads");
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

            APSI_LOG_INFO("Finished processing query request");
        }

        void Sender::QueryWorker(
            const shared_ptr<SenderDB> &sender_db,
            CryptoContext crypto_context,
            pair<uint32_t, uint32_t> work_range,
            vector<CiphertextPowers> &all_powers,
            const PowersDag &pd,
            Channel &chl,
            function<void(Channel &, unique_ptr<ResultPackage>)> send_rp_fun)
        {
            stringstream sw_ss;
            sw_ss << "Sender::QueryWorker [" << this_thread::get_id() << "]";
            STOPWATCH(sender_stopwatch, sw_ss.str());

            uint32_t bundle_idx_start = work_range.first;
            uint32_t bundle_idx_end = work_range.second;

            APSI_LOG_INFO("Query worker [" << this_thread::get_id() << "]: "
                "start processing bundle indices [" << bundle_idx_start << ", " << bundle_idx_end << ")");

            // Compute the powers for each bundle index and loop over the BinBundles
            Evaluator &evaluator = *crypto_context.evaluator();
            RelinKeys &relin_keys = *crypto_context.relin_keys();
            for (uint32_t bundle_idx = bundle_idx_start; bundle_idx < bundle_idx_end; bundle_idx++)
            {
                auto bundle_caches = sender_db->get_cache_at(bundle_idx);
                size_t bundle_count = bundle_caches.size();
                if (!bundle_count)
                {
                    APSI_LOG_DEBUG("Query worker [" << this_thread::get_id() << "]: "
                        "no bin bundles found at bundle index " << bundle_idx);
                    continue;
                }

                // Compute all powers of the query
                APSI_LOG_DEBUG("Query worker [" << this_thread::get_id() << "]: "
                    "computing all query ciphertext powers for bundle index " << bundle_idx);

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

                // Now that all powers of the ciphertext have been computed, we need to transform them to NTT form. This
                // will substantially improve the polynomial evaluation (below), because the plaintext polynomials are
                // already in NTT transformed form, and the ciphertexts are used repeatedly for each bin bundle at this
                // index. This computation is separate from the graph processing above, because the multiplications must
                // all be done before transforming to NTT form. We omit the first ciphertext in the vector, because it
                // corresponds to the zeroth power of the query and is included only for convenience of the indexing;
                // the ciphertext is actually not set or valid for use.
                //
                // When using C++17 this function may be multi-threaded in the future with C++ execution policies.
                seal_for_each_n(powers_at_this_bundle_idx.begin() + 1, powers_at_this_bundle_idx.size() - 1, [&](auto &ct) {
                    evaluator.transform_to_ntt_inplace(ct);
                });

                // Next, iterate over each bundle with this bundle index
                APSI_LOG_DEBUG("Query worker [" << this_thread::get_id() << "]: "
                    "start processing " << bundle_count << " bin bundles for bundle index " << bundle_idx);

                // When using C++17 this function may be multi-threaded in the future with C++ execution policies
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
                    APSI_LOG_DEBUG("Query worker [" << this_thread::get_id() << "]: "
                        "sending result package for bundle index " << bundle_idx);
                    send_rp_fun(chl, move(rp));
                });

                APSI_LOG_DEBUG("Query worker [" << this_thread::get_id() << "]: "
                    "finished processing " << bundle_count << " bin bundles for bundle index " << bundle_idx);
            }

            APSI_LOG_INFO("Query worker [" << this_thread::get_id() << "]: "
                "finished processing bundle indices [" << bundle_idx_start << ", " << bundle_idx_end << ")");
        }
    } // namespace sender
} // namespace apsi
