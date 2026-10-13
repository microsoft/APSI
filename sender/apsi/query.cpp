// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <stdexcept>
#include <string>

// APSI
#include "apsi/log.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"

using namespace std;
using namespace seal;

namespace apsi {
    using namespace network;
    using namespace util;

    namespace sender {
        namespace {
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
            result.sender_db_ = sender_db_;
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

            // Extract and validate query ciphertexts
            for (auto &q : query_request->data) {
                APSI_LOG_DEBUG(
                    "Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                vector<Ciphertext> cts;
                for (auto &ct : q.second) {
                    cts.push_back(ct.extract(seal_context));
                    if (!is_valid_for(cts.back(), *seal_context)) {
                        APSI_LOG_ERROR("Extracted ciphertext is invalid for SEALContext");
                        return;
                    }

                    // is_valid_for only checks internal consistency: it accepts a ciphertext at
                    // any level of the modulus chain, of any size, and in either NTT or
                    // coefficient form. An honest receiver always sends freshly encrypted source
                    // powers and Sender::ComputePowers depends on that, so anything else must be
                    // rejected here: operands at mixed levels or in NTT form make
                    // Evaluator::multiply throw, and a size greater than 2 outruns the
                    // relinearization keys. Either throw escapes into a worker thread.
                    if (cts.back().parms_id() != seal_context->first_parms_id()) {
                        APSI_LOG_ERROR(
                            "Extracted ciphertext is not at the highest level of the "
                            "modulus chain");
                        return;
                    }
                    if (cts.back().size() != 2) {
                        APSI_LOG_ERROR(
                            "Extracted ciphertext has size " << cts.back().size()
                                                             << "; expected a fresh encryption of "
                                                                "size 2");
                        return;
                    }
                    if (cts.back().is_ntt_form()) {
                        APSI_LOG_ERROR(
                            "Extracted ciphertext is in NTT form; expected coefficient form");
                        return;
                    }
                }
                data_[q.first] = std::move(cts);
            }

            // Get the PSIParams
            PSIParams params(sender_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params.query_params().ps_low_degree;
            const set<uint32_t> &query_powers = params.query_params().query_powers;
            set<uint32_t> target_powers = create_powers_set(ps_low_degree, max_items_per_bin);

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

            // Check that the query data size matches the PSIParams
            if (data_.size() != query_powers.size()) {
                APSI_LOG_ERROR(
                    "Extracted query data is incompatible with PSI parameters: "
                    "query contains "
                    << data_.size()
                    << " ciphertext powers which does not match with "
                       "the size of query_powers ("
                    << query_powers.size() << ")");
                return;
            }

            for (auto &q : data_) {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count) {
                    APSI_LOG_ERROR(
                        "Extracted query data is incompatible with PSI parameters: "
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
                        "Extracted query data is incompatible with PowersDag: "
                        "query power "
                        << q.first << " does not match with a source node in PowersDag");
                    return;
                }
            }

            // The query is valid
            valid_ = true;
        }
    } // namespace sender
} // namespace apsi
