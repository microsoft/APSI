// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <future>
#include <sstream>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/log.h"
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/psi_params.h"
#include "apsi/seal_object.h"
#include "apsi/sender.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/stopwatch.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/evaluator.h"
#include "seal/modulus.h"
#include "seal/util/common.h"
#include "seal/util/iterator.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi {
    using namespace util;
    using namespace oprf;
    using namespace network;

    namespace sender {
        void Sender::RunParams(
            const ParamsRequest &params_request,
            shared_ptr<SenderDB> sender_db,
            network::Channel &chl,
            function<void(Channel &, Response)> send_fun)
        {
            STOPWATCH(sender_stopwatch, "Sender::RunParams");

            if (!params_request) {
                APSI_LOG_ERROR("Failed to process parameter request: request is invalid");
                throw invalid_argument("request is invalid");
            }

            // Check that the database is set
            if (!sender_db) {
                throw logic_error("SenderDB is not set");
            }

            APSI_LOG_INFO("Start processing parameter request");

            ParamsResponse response_params = make_unique<ParamsResponse::element_type>();
            response_params->params = make_unique<PSIParams>(sender_db->get_params());

            try {
                send_fun(chl, move(response_params));
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Failed to send response to parameter request; function threw an exception: "
                    << ex.what());
                throw;
            }

            APSI_LOG_INFO("Finished processing parameter request");
        }

        void Sender::RunOPRF(
            const OPRFRequest &oprf_request,
            OPRFKey key,
            network::Channel &chl,
            function<void(Channel &, Response)> send_fun)
        {
            STOPWATCH(sender_stopwatch, "Sender::RunOPRF");

            if (!oprf_request) {
                APSI_LOG_ERROR("Failed to process OPRF request: request is invalid");
                throw invalid_argument("request is invalid");
            }

            APSI_LOG_INFO(
                "Start processing OPRF request for " << oprf_request->data.size() / oprf_query_size
                                                     << " items");

            // OPRF response has the same size as the OPRF query
            OPRFResponse response_oprf = make_unique<OPRFResponse::element_type>();
            try {
                response_oprf->data = OPRFSender::ProcessQueries(oprf_request->data, key);
            } catch (const exception &ex) {
                // Something was wrong with the OPRF request. This can mean malicious
                // data being sent to the sender in an attempt to extract OPRF key.
                // Best not to respond anything.
                APSI_LOG_ERROR("Processing OPRF request threw an exception: " << ex.what());
                return;
            }

            try {
                send_fun(chl, move(response_oprf));
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Failed to send response to OPRF request; function threw an exception: "
                    << ex.what());
                throw;
            }

            APSI_LOG_INFO("Finished processing OPRF request");
        }

        void Sender::RunQuery(
            const Query &query,
            Channel &chl,
            function<void(Channel &, Response)> send_fun,
            function<void(Channel &, ResultPart)> send_rp_fun)
        {
            if (!query) {
                APSI_LOG_ERROR("Failed to process query request: query is invalid");
                throw invalid_argument("query is invalid");
            }

            ThreadPoolMgr tpm;

            auto sender_db = query.sender_db();

            // Acquire read lock on SenderDB
            auto sender_db_lock = sender_db->get_reader_lock();

            STOPWATCH(sender_stopwatch, "Sender::RunQuery");
            APSI_LOG_INFO(
                "Start processing query request on database with " << sender_db->get_item_count()
                                                                   << " items");

            // Copy over the CryptoContext from SenderDB; set the Evaluator for this local instance
            CryptoContext crypto_context(sender_db->get_crypto_context());
            crypto_context.set_evaluator(query.relin_keys());

            // Get the PSIParams
            PSIParams params(sender_db->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;

            // Extract the PowersDag
            PowersDag pd = query.pd();

            // The query response only tells how many ResultPackages to expect; send this first
            uint32_t package_count = safe_cast<uint32_t>(sender_db->get_bin_bundle_count());
            QueryResponse response_query = make_unique<QueryResponse::element_type>();
            response_query->package_count = package_count;

            try {
                send_fun(chl, move(response_query));
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Failed to send response to query request; function threw an exception: "
                    << ex.what());
                throw;
            }

            // For each bundle index i, we need a vector of powers of the query Qᵢ. We need powers
            // all the way up to Qᵢ^max_items_per_bin (maybe less if the BinBundles aren't as full
            // as expected). We don't store the zeroth power.
            vector<CiphertextPowers> all_powers(bundle_idx_count);

            // Initialize powers
            for (CiphertextPowers &powers : all_powers) {
                // The + 1 is because we index by power. The 0th power is a dummy value. I promise
                // this makes things easier to read.
                powers.resize(static_cast<size_t>(max_items_per_bin) + 1);
            }

            // Load inputs provided in the query
            for (auto &q : query.data()) {
                // The exponent of all the query powers we're about to iterate through
                size_t exponent = static_cast<size_t>(q.first);

                // Load Qᵢᵉ for all bundle indices i, where e is the exponent specified above
                for (size_t bundle_idx = 0; bundle_idx < all_powers.size(); bundle_idx++) {
                    // Load input^power to all_powers[bundle_idx][exponent]
                    APSI_LOG_DEBUG(
                        "Extracting query ciphertext power " << exponent << " for bundle index "
                                                             << bundle_idx);
                    all_powers[bundle_idx][exponent] = move(q.second[bundle_idx]);
                }
            }

            // Compute query powers for the bundle indexes
            for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
                ComputePowers(
                    sender_db, crypto_context, all_powers, pd, static_cast<uint32_t>(bundle_idx));
            }

            APSI_LOG_DEBUG("Finished computing powers for all bundle indices");
            APSI_LOG_DEBUG("Start processing bin bundle caches");

            vector<future<void>> futures;
            for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
                auto bundle_caches = sender_db->get_cache_at(static_cast<uint32_t>(bundle_idx));
                for (auto &cache : bundle_caches) {
                    futures.push_back(tpm.thread_pool().enqueue([&, bundle_idx, cache]() {
                        ProcessBinBundleCache(
                            query.relin_keys(),
                            sender_db,
                            cache,
                            all_powers,
                            chl,
                            send_rp_fun,
                            static_cast<uint32_t>(bundle_idx),
                            query.compr_mode());
                    }));
                }
            }

            // Wait until all bin bundle caches have been processed
            for (auto &f : futures) {
                f.get();
            }

            APSI_LOG_INFO("Finished processing query request");
        }

        void Sender::ComputePowers(
            const shared_ptr<SenderDB> &sender_db,
            CryptoContext &crypto_context,
            vector<CiphertextPowers> &all_powers,
            const PowersDag &pd,
            uint32_t bundle_idx)
        {
            STOPWATCH(sender_stopwatch, "Sender::ComputePowers");
            auto bundle_caches = sender_db->get_cache_at(bundle_idx);
            if (!bundle_caches.size()) {
                return;
            }

            // Compute all powers of the query
            APSI_LOG_DEBUG("Computing all query ciphertext powers for bundle index " << bundle_idx);

            Evaluator &evaluator = *crypto_context.evaluator();
            RelinKeys &relin_keys = *crypto_context.relin_keys();

            CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
            bool relinearize = crypto_context.seal_context()->using_keyswitching();
            pd.parallel_apply([&](const PowersDag::PowersNode &node) {
                if (!node.is_source()) {
                    auto parents = node.parents;
                    Ciphertext prod;
                    evaluator.multiply(
                        powers_at_this_bundle_idx[parents.first],
                        powers_at_this_bundle_idx[parents.second],
                        prod);
                    if (relinearize) {
                        evaluator.relinearize_inplace(prod, relin_keys);
                    }
                    powers_at_this_bundle_idx[node.power] = move(prod);
                }
            });

            // Now that all powers of the ciphertext have been computed, we need to transform them
            // to NTT form. This will substantially improve the polynomial evaluation (below),
            // because the plaintext polynomials are already in NTT transformed form, and the
            // ciphertexts are used repeatedly for each bin bundle at this index. This computation
            // is separate from the graph processing above, because the multiplications must all be
            // done before transforming to NTT form. We omit the first ciphertext in the vector,
            // because it corresponds to the zeroth power of the query and is included only for
            // convenience of the indexing; the ciphertext is actually not set or valid for use.

            ThreadPoolMgr tpm;
            vector<future<void>> futures;
            for (auto ct_iter = next(powers_at_this_bundle_idx.begin());
                 ct_iter != powers_at_this_bundle_idx.end();
                 ct_iter++) {
                futures.push_back(tpm.thread_pool().enqueue(
                    [&, ct_iter]() { evaluator.transform_to_ntt_inplace(*ct_iter); }));
            }

            for (auto &f : futures) {
                f.get();
            }
        }

        void Sender::ProcessBinBundleCache(
            const RelinKeys &relin_keys,
            const shared_ptr<SenderDB> &sender_db,
            const reference_wrapper<const BinBundleCache> &cache,
            vector<CiphertextPowers> &all_powers,
            Channel &chl,
            function<void(Channel &, ResultPart)> send_rp_fun,
            uint32_t bundle_idx,
            compr_mode_type compr_mode)
        {
            STOPWATCH(sender_stopwatch, "Sender::ProcessBinBundleCache");

            // Package for the result data
            auto rp = make_unique<ResultPackage>();
            rp->compr_mode = compr_mode;

            rp->bundle_idx = bundle_idx;
            rp->nonce_byte_count = safe_cast<uint32_t>(sender_db->get_nonce_byte_count());
            rp->label_byte_count = safe_cast<uint32_t>(sender_db->get_label_byte_count());

            // Compute the matching result and move to rp
            const BatchedPlaintextPolyn &matching_polyn = cache.get().batched_matching_polyn;
            //rp->psi_result = matching_polyn.eval(all_powers[bundle_idx]);
            rp->psi_result = matching_polyn.eval_patstock(relin_keys, all_powers[bundle_idx], sender_db->get_bin_bundle_count(bundle_idx));


            for (const auto &interp_polyn : cache.get().batched_interp_polyns) {
                // Compute the label result and move to rp
                rp->label_result.emplace_back(interp_polyn.eval(all_powers[bundle_idx]));
            }

            // Send this result part
            try {
                send_rp_fun(chl, move(rp));
            } catch (const exception &ex) {
                APSI_LOG_ERROR(
                    "Failed to send result part; function threw an exception: " << ex.what());
                throw;
            }
        }
    } // namespace sender
} // namespace apsi
