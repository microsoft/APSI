// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <future>
#include <mutex>
#include <thread>

// APSI
#include "apsi/log.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/stopwatch.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"

using namespace std;
using namespace seal;

namespace apsi {
    using namespace util;

    namespace oprf {
        bool OPRFKey::operator==(const OPRFKey &compare) const
        {
            return compare_bytes(oprf_key_.cbegin(), compare.oprf_key_.cbegin(), oprf_key_size);
        }

        void OPRFKey::save(oprf_key_span_type oprf_key) const
        {
            copy_bytes(oprf_key_.cbegin(), oprf_key_size, oprf_key.data());
        }

        void OPRFKey::load(oprf_key_span_const_type oprf_key)
        {
            copy_bytes(oprf_key.data(), oprf_key_size, oprf_key_.begin());
        }

        void OPRFKey::save(ostream &stream) const
        {
            auto old_except_mask = stream.exceptions();
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            try {
                stream.write(reinterpret_cast<const char *>(oprf_key_.cbegin()), oprf_key_size);
            } catch (const ios_base::failure &) {
                stream.exceptions(old_except_mask);
                throw runtime_error("I/O error");
            }
            stream.exceptions(old_except_mask);
        }

        void OPRFKey::load(istream &stream)
        {
            auto old_except_mask = stream.exceptions();
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            try {
                stream.read(reinterpret_cast<char *>(oprf_key_.begin()), oprf_key_size);
            } catch (const ios_base::failure &) {
                stream.exceptions(old_except_mask);
                throw runtime_error("I/O error");
            }
            stream.exceptions(old_except_mask);
        }

        vector<unsigned char> OPRFSender::ProcessQueries(
            gsl::span<const unsigned char> oprf_queries, const OPRFKey &oprf_key)
        {
            if (oprf_queries.size() % oprf_query_size) {
                throw invalid_argument("oprf_queries has invalid size");
            }

            STOPWATCH(sender_stopwatch, "OPRFSender::ProcessQueries");

            size_t query_count = oprf_queries.size() / oprf_query_size;
            vector<unsigned char> oprf_responses(query_count * oprf_response_size);

            auto oprf_in_ptr = oprf_queries.data();
            auto oprf_out_ptr = oprf_responses.data();

            ThreadPoolMgr tpm;
            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), query_count);
            vector<future<void>> futures(task_count);

            auto ProcessQueriesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < query_count; idx += step) {
                    // Load the point from input buffer
                    ECPoint ecpt;
                    ecpt.load(ECPoint::point_save_span_const_type{
                        oprf_in_ptr + idx * oprf_query_size, oprf_query_size });

                    // Multiply with key
                    if (!ecpt.scalar_multiply(oprf_key.key_span(), true)) {
                        throw logic_error("scalar multiplication failed due to invalid query data");
                    }

                    // Save the result to oprf_responses
                    ecpt.save(ECPoint::point_save_span_type{
                        oprf_out_ptr + idx * oprf_response_size, oprf_response_size });
                }
            };

            for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
                futures[thread_idx] =
                    tpm.thread_pool().enqueue(ProcessQueriesLambda, thread_idx, task_count);
            }

            for (auto &f : futures) {
                f.get();
            }

            return oprf_responses;
        }

        pair<HashedItem, LabelKey> OPRFSender::GetItemHash(
            const Item &item, const OPRFKey &oprf_key)
        {
            // Create an elliptic curve point from the item
            ECPoint ecpt(item.get_as<const unsigned char>());

            // Multiply with key
            ecpt.scalar_multiply(oprf_key.key_span(), true);

            // Extract the item hash and the label encryption key
            array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
            ecpt.extract_hash(item_hash_and_label_key);

            // The first 128 bits represent the item hash; the next 128 bits represent the
            // label encryption key.
            pair<HashedItem, LabelKey> result;
            copy_bytes(item_hash_and_label_key.data(), oprf_hash_size, result.first.value().data());
            copy_bytes(
                item_hash_and_label_key.data() + oprf_hash_size,
                label_key_byte_count,
                result.second.data());

            return result;
        }

        vector<HashedItem> OPRFSender::ComputeHashes(
            const gsl::span<const Item> &oprf_items, const OPRFKey &oprf_key)
        {
            STOPWATCH(sender_stopwatch, "OPRFSender::ComputeHashes (unlabeled)");
            APSI_LOG_DEBUG("Start computing OPRF hashes for " << oprf_items.size() << " items");

            ThreadPoolMgr tpm;
            vector<HashedItem> oprf_hashes(oprf_items.size());
            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), oprf_items.size());
            vector<future<void>> futures(task_count);

            auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < oprf_items.size(); idx += step) {
                    oprf_hashes[idx] = GetItemHash(oprf_items[idx], oprf_key).first;
                }
            };

            for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
                futures[thread_idx] =
                    tpm.thread_pool().enqueue(ComputeHashesLambda, thread_idx, task_count);
            }

            for (auto &f : futures) {
                f.get();
            }

            APSI_LOG_DEBUG("Finished computing OPRF hashes for " << oprf_items.size() << " items");

            return oprf_hashes;
        }

        vector<pair<HashedItem, EncryptedLabel>> OPRFSender::ComputeHashes(
            const gsl::span<const pair<Item, Label>> &oprf_item_labels,
            const OPRFKey &oprf_key,
            size_t label_byte_count,
            size_t nonce_byte_count)
        {
            if (nonce_byte_count > max_nonce_byte_count) {
                throw invalid_argument("nonce_byte_count is too large");
            }

            STOPWATCH(sender_stopwatch, "OPRFSender::ComputeHashes (labeled)");
            APSI_LOG_DEBUG(
                "Start computing OPRF hashes and encrypted labels for " << oprf_item_labels.size()
                                                                        << " item-label pairs");

            ThreadPoolMgr tpm;
            vector<pair<HashedItem, EncryptedLabel>> oprf_hashes(oprf_item_labels.size());
            size_t task_count =
                min<size_t>(ThreadPoolMgr::GetThreadCount(), oprf_item_labels.size());
            vector<future<void>> futures(task_count);

            auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < oprf_item_labels.size(); idx += step) {
                    const Item &item = oprf_item_labels[idx].first;
                    const Label &label = oprf_item_labels[idx].second;

                    HashedItem hashed_item;
                    LabelKey key;
                    tie(hashed_item, key) = GetItemHash(item, oprf_key);

                    // Encrypt here
                    EncryptedLabel encrypted_label =
                        encrypt_label(label, key, label_byte_count, nonce_byte_count);

                    // Set result
                    oprf_hashes[idx] = make_pair(hashed_item, move(encrypted_label));
                }
            };

            for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
                futures[thread_idx] =
                    tpm.thread_pool().enqueue(ComputeHashesLambda, thread_idx, task_count);
            }

            for (auto &f : futures) {
                f.get();
            }

            APSI_LOG_DEBUG(
                "Finished computing OPRF hashes and encrypted labels for "
                << oprf_item_labels.size() << " item-label pairs");

            return oprf_hashes;
        }
    } // namespace oprf
} // namespace apsi
