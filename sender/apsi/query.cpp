// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"
#include "apsi/seal_object.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/task_group.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;

namespace apsi {
    using namespace network;
    using namespace util;

    namespace sender {
        namespace {
            // A query ciphertext held in serialized form must take at least 1/max_query_expansion
            // of the bytes it would load to; see Query::Query
            constexpr size_t max_query_expansion = 64;

            /**
            Returns true if a SenderDB with the given parameters must refuse a query that carries
            no parameter fingerprint. Receivers before APSI 2.0 send none, and cannot use the
            answer of a SenderDB with match tags: their schema requires a PSI result, which such
            an answer does not have, so their query fails at the first result package. The query
            is refused rather than evaluated for nothing.
            */
            bool requires_params_fingerprint(const PSIParams &params)
            {
                return params.uses_tags();
            }

            /**
            Returns the fingerprint in lowercase hexadecimal, for log messages.
            */
            string to_hex(const PSIParams::Fingerprint &fingerprint)
            {
                static constexpr array<char, 17> hex_digits{ "0123456789abcdef" };

                string out;
                out.reserve(2 * fingerprint.size());
                for (unsigned char byte : fingerprint) {
                    out += hex_digits[byte >> 4];
                    out += hex_digits[byte & 0x0F];
                }
                return out;
            }
        } // namespace

        Query Query::deep_copy() const
        {
            Query result;
            result.relin_keys_ = relin_keys_;
            result.data_ = data_;
            result.pd_ = pd_;
            result.sender_db_ = sender_db_;
            result.valid_ = valid_;
            result.compr_mode_ = compr_mode_;
            result.params_fingerprint_ = params_fingerprint_;

            return result;
        }

        bool Query::check_params_fingerprint(const PSIParams &params) const
        {
            if (!params_fingerprint_) {
                if (requires_params_fingerprint(params)) {
                    APSI_LOG_ERROR(
                        "Query carries no parameter fingerprint, as queries from receivers before "
                        "APSI 2.0 do not, but such receivers cannot use the SenderDB's parameters");
                    return false;
                }

                return true;
            }

            PSIParams::Fingerprint expected = params.fingerprint();
            if (*params_fingerprint_ != expected) {
                APSI_LOG_ERROR(
                    "Query was created for different parameters than the SenderDB uses: its "
                    "parameter fingerprint is "
                    << to_hex(*params_fingerprint_) << " but the SenderDB's is "
                    << to_hex(expected));
                return false;
            }

            return true;
        }

        Query::Query(QueryRequest query_request, shared_ptr<SenderDB> sender_db)
        {
            if (!sender_db) {
                throw invalid_argument("sender_db cannot be null");
            }
            if (!query_request) {
                throw invalid_argument("query_request cannot be null");
            }

            compr_mode_ = query_request->compr_mode;
            params_fingerprint_ = query_request->params_fingerprint;

            sender_db_ = std::move(sender_db);
            auto seal_context = sender_db_->get_seal_context();

            // A query created for other parameters is refused before anything is extracted from it
            if (!check_params_fingerprint(sender_db_->get_params())) {
                return;
            }

            // Extract and validate relinearization keys
            if (seal_context->using_keyswitching()) {
                relin_keys_ = query_request->relin_keys.extract(seal_context);
                if (!is_valid_for(relin_keys_, *seal_context)) {
                    APSI_LOG_ERROR("Extracted relinearization keys are invalid for SEALContext");
                    return;
                }
            }

            // Get the PSIParams
            PSIParams params(sender_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params.query_params().ps_low_degree;
            const set<uint32_t> &query_powers = params.query_params().query_powers;
            set<uint32_t> target_powers = create_powers_set(ps_low_degree, max_items_per_bin);

            // Check that the query data matches the PSIParams before extracting any ciphertext.
            // SEAL compresses what it saves, so a query that arrived over the network can hold far
            // more ciphertext data than its size suggests, and extracting a ciphertext loads it in
            // full. Checking the counts first means that an invalid query can make the sender
            // load no more ciphertexts than a valid one holds.
            if (query_request->data.size() != query_powers.size()) {
                APSI_LOG_ERROR(
                    "Query data is incompatible with PSI parameters: "
                    "query contains "
                    << query_request->data.size()
                    << " ciphertext powers which does not match with "
                       "the size of query_powers ("
                    << query_powers.size() << ")");
                return;
            }

            for (const auto &q : query_request->data) {
                // Check that each power has one ciphertext per bundle index and is a source node in
                // the PowersDag
                if (q.second.size() != bundle_idx_count) {
                    APSI_LOG_ERROR(
                        "Query data is incompatible with PSI parameters: "
                        "query power "
                        << q.first << " contains " << q.second.size()
                        << " ciphertexts which does not "
                           "match with bundle_idx_count ("
                        << bundle_idx_count << ")");
                    return;
                }

                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) {
                    return n == q.first;
                });
                if (where == query_powers.cend()) {
                    APSI_LOG_ERROR(
                        "Query data is incompatible with PowersDag: "
                        "query power "
                        << q.first << " does not match with a source node in PowersDag");
                    return;
                }
            }

            // Extract and validate query ciphertexts. Each is checked as soon as it is extracted,
            // and once one has failed no other is taken, so that an invalid query costs the sender
            // at most one invalid ciphertext for each task extracting them at once. They are
            // extracted on the calling thread if ThreadPoolMgr::GetThreadCount() is one, as it is
            // under a ScopedParallelismLimit of one, or if the calling thread is a task of the
            // thread pool, and otherwise by up to that many tasks on the thread pool, each taking
            // the next ciphertext in the order of the query data. Every ciphertext before the last
            // one taken has then been checked, so the failure reported, the first in that order, is
            // the one that extracting them one at a time reports.
            //
            // As defense in depth, one held in serialized form, as one that arrived over the
            // network is, must also take at least 1/max_query_expansion of the bytes it would load
            // to, a fresh encryption of size 2 at the first level of the modulus chain, before it
            // is extracted. SEAL compresses what it saves, so a ciphertext whose data is zero would
            // otherwise load to hundreds or thousands of times its size, while a fresh encryption
            // looks uniformly random and stays far above the bound even when saved with a seed.
            // SEAL itself bounds what the relinearization keys load to.
            const auto &first_parms = seal_context->first_context_data()->parms();
            size_t loaded_ct_byte_count = seal::util::mul_safe(
                static_cast<size_t>(2),
                first_parms.poly_modulus_degree(),
                first_parms.coeff_modulus().size(),
                sizeof(uint64_t));

            // The ciphertexts in the order of the query data, with their exponents
            vector<pair<uint32_t, SEALObject<Ciphertext> *>> sources;
            for (auto &q : query_request->data) {
                APSI_LOG_DEBUG(
                    "Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                for (auto &ct : q.second) {
                    sources.emplace_back(q.first, &ct);
                }
            }

            // Extracts the ciphertext at the given index into ct and checks it. Returns an empty
            // string if it passes, and why it fails otherwise.
            auto extract_and_check = [&](size_t idx, Ciphertext &ct) -> string {
                auto &[exponent, source] = sources[idx];
                ostringstream failure;

                if (source->is_serialized()) {
                    // For an object held in serialized form, this is the number of bytes it is
                    // held as, whatever the compression mode
                    size_t ct_byte_count = source->save_size(compr_mode_type::none);
                    if (ct_byte_count < loaded_ct_byte_count / max_query_expansion) {
                        failure << "Failed to extract a ciphertext for exponent " << exponent
                                << ": it takes " << ct_byte_count << " bytes, less than 1/"
                                << max_query_expansion << " of the " << loaded_ct_byte_count
                                << " bytes it would load to";
                        return failure.str();
                    }
                }

                // A ciphertext that arrived over the network is loaded only here, and its data
                // may not be a valid ciphertext at all
                try {
                    ct = source->extract(seal_context);
                } catch (const exception &ex) {
                    failure << "Failed to extract a ciphertext for exponent " << exponent << ": "
                            << ex.what();
                    return failure.str();
                }
                if (!is_valid_for(ct, *seal_context)) {
                    return "Extracted ciphertext is invalid for SEALContext";
                }

                // is_valid_for only checks internal consistency: it accepts a ciphertext at any
                // level of the modulus chain, of any size, and in either NTT or coefficient form.
                // An honest receiver always sends freshly encrypted source powers and
                // Sender::ComputePowers depends on that, so anything else must be rejected here:
                // operands at mixed levels or in NTT form make Evaluator::multiply throw, and a
                // size greater than 2 outruns the relinearization keys. Either throw escapes into
                // a worker thread.
                if (ct.parms_id() != seal_context->first_parms_id()) {
                    return "Extracted ciphertext is not at the highest level of the modulus chain";
                }
                if (ct.size() != 2) {
                    failure << "Extracted ciphertext has size " << ct.size()
                            << "; expected a fresh encryption of size 2";
                    return failure.str();
                }
                if (ct.is_ntt_form()) {
                    return "Extracted ciphertext is in NTT form; expected coefficient form";
                }

                return {};
            };

            vector<Ciphertext> cts(sources.size());
            vector<string> failures(sources.size());
            atomic<size_t> next_idx{ 0 };
            atomic<bool> failed{ false };
            auto extract_in_order = [&]() {
                while (!failed) {
                    size_t idx = next_idx++;
                    if (idx >= sources.size()) {
                        return;
                    }
                    failures[idx] = extract_and_check(idx, cts[idx]);
                    if (!failures[idx].empty()) {
                        failed = true;
                    }
                }
            };

            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), sources.size());
            if (task_count > 1) {
                ThreadPoolMgr tpm;
                if (tpm.thread_pool().is_worker_thread()) {
                    // A task of the thread pool cannot wait for other tasks on it (see TaskGroup),
                    // so on one the ciphertexts are extracted as with a single thread
                    task_count = 1;
                } else {
                    TaskGroup tasks(tpm.thread_pool());
                    for (size_t task_idx = 0; task_idx < task_count; task_idx++) {
                        tasks.add(extract_in_order);
                    }
                    tasks.join();
                }
            }
            if (task_count <= 1) {
                extract_in_order();
            }
            APSI_LOG_DEBUG(
                "Extracted " << min<size_t>(next_idx, sources.size()) << " of " << sources.size()
                             << " query ciphertexts with " << max<size_t>(task_count, 1)
                             << " tasks");

            for (const auto &failure : failures) {
                if (!failure.empty()) {
                    APSI_LOG_ERROR(failure);
                    return;
                }
            }

            for (size_t idx = 0; idx < sources.size(); idx++) {
                data_[sources[idx].first].push_back(std::move(cts[idx]));
            }

            // Create the PowersDag
            pd_.configure(query_powers, target_powers);

            // Check that the PowersDag is valid
            if (!pd_.is_configured()) {
                APSI_LOG_ERROR(
                    "Failed to configure PowersDag ("
                    << "source_powers: " << to_string(query_powers) << ", "
                    << "up_to_power: " << to_string(target_powers) << ")");
                return;
            }
            APSI_LOG_DEBUG("Configured PowersDag with depth " << pd_.depth());

            // The query is valid
            valid_ = true;
        }
    } // namespace sender
} // namespace apsi
