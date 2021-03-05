// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <future>
#include <thread>
#include <mutex>

// APSI
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"
#include "apsi/util/thread_pool_mgr.h"

using namespace std;
using namespace seal;


namespace apsi
{
    using namespace util;

    namespace oprf
    {
        void OPRFKey::save(oprf_key_span_type oprf_key) const
        {
            copy_n(oprf_key_.cbegin(), oprf_key_size, oprf_key.data());
        }

        void OPRFKey::load(oprf_key_span_const_type oprf_key)
        {
            copy_n(oprf_key.data(), oprf_key_size, oprf_key_.begin());
        }

        void OPRFKey::save(ostream &stream) const
        {
            auto old_except_mask = stream.exceptions();
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            try
            {
                stream.write(reinterpret_cast<const char *>(oprf_key_.cbegin()), oprf_key_size);
            }
            catch (const ios_base::failure &)
            {
                stream.exceptions(old_except_mask);
                throw runtime_error("I/O error");
            }
            stream.exceptions(old_except_mask);
        }

        void OPRFKey::load(istream &stream)
        {
            auto old_except_mask = stream.exceptions();
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            try
            {
                stream.read(reinterpret_cast<char *>(oprf_key_.begin()), oprf_key_size);
            }
            catch (const ios_base::failure &)
            {
                stream.exceptions(old_except_mask);
                throw runtime_error("I/O error");
            }
            stream.exceptions(old_except_mask);
        }

        vector<seal_byte> OPRFSender::ProcessQueries(
            gsl::span<const seal_byte> oprf_queries, const OPRFKey &oprf_key)
        {
            if (oprf_queries.size() % oprf_query_size)
            {
                throw invalid_argument("oprf_queries has invalid size");
            }

            size_t query_count = oprf_queries.size() / oprf_query_size;
            vector<seal_byte> oprf_responses(query_count * oprf_response_size);

            auto oprf_in_ptr = reinterpret_cast<const unsigned char *>(oprf_queries.data());
            auto oprf_out_ptr = reinterpret_cast<unsigned char *>(oprf_responses.data());

            for (size_t i = 0; i < query_count; i++)
            {
                // Load the point from items_buffer
                ECPoint ecpt;
                ecpt.load(ECPoint::point_save_span_const_type{ oprf_in_ptr, oprf_query_size });

                // Multiply with key
                if (!ecpt.scalar_multiply(oprf_key.key_span(), true))
                {
                    throw logic_error("scalar multiplication failed due to invalid query data");
                }

                // Save the result to oprf_responses
                ecpt.save(ECPoint::point_save_span_type{ oprf_out_ptr, oprf_response_size });

                // Move forward
                advance(oprf_in_ptr, oprf_query_size);
                advance(oprf_out_ptr, oprf_response_size);
            }

            return oprf_responses;
        }

        vector<oprf_hash_type> OPRFSender::ComputeHashes(
            const gsl::span<const oprf_item_type> &oprf_items, const OPRFKey &oprf_key)
        {
            ThreadPoolMgr tpm;
            vector<oprf_hash_type> oprf_hashes(oprf_items.size());
            vector<future<void>> futures(ThreadPoolMgr::get_thread_count());

            auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < oprf_items.size(); idx += step) {
                    const oprf_item_type &item = oprf_items[idx];

                    // Create an elliptic curve point from the item
                    ECPoint ecpt(item.get_as<const unsigned char>());

                    // Multiply with key
                    ecpt.scalar_multiply(oprf_key.key_span(), true);

                    // Extract the item hash and the label encryption key
                    array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
                    ecpt.extract_hash(item_hash_and_label_key);

                    // The first 128 bits represent the item hash; the next 128 bits represent the
                    // label encryption key and are discarded in this overload of ComputeHashes
                    oprf_hash_type hash;
                    copy_n(
                        item_hash_and_label_key.data(),
                        oprf_hash_size,
                        hash.get_as<unsigned char>().data());

                    // Set result
                    oprf_hashes[idx] = hash;
                }
            };

            for (size_t thread_idx = 0; thread_idx < ThreadPoolMgr::get_thread_count();
                 thread_idx++) {
                futures[thread_idx] = tpm.thread_pool().enqueue(
                    ComputeHashesLambda, thread_idx, ThreadPoolMgr::get_thread_count());
            }

            for (auto &f : futures) {
                f.get();
            }

            return oprf_hashes;
        }

        vector<pair<oprf_hash_type, EncryptedLabel>> OPRFSender::ComputeHashes(
            const gsl::span<const pair<oprf_item_type, Label>> &oprf_item_labels,
            const OPRFKey &oprf_key)
        {
            ThreadPoolMgr tpm;
            vector<pair<oprf_hash_type, EncryptedLabel>> oprf_hashes(oprf_item_labels.size());
            vector<future<void>> futures(ThreadPoolMgr::get_thread_count());

            auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < oprf_item_labels.size(); idx += step) {
                    const pair<oprf_item_type, Label> &item = oprf_item_labels[idx];

                    // Create an elliptic curve point from the item
                    ECPoint ecpt(item.first.get_as<const unsigned char>());

                    // Multiply with key
                    ecpt.scalar_multiply(oprf_key.key_span(), true);

                    // Extract the item hash and the label encryption key
                    array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
                    ecpt.extract_hash(item_hash_and_label_key);

                    // The first 128 bits represent the item hash; the next 128 bits represent
                    // the label encryption key
                    pair<oprf_hash_type, Label> hash;
                    copy_n(
                        item_hash_and_label_key.data(),
                        oprf_hash_size,
                        hash.first.get_as<unsigned char>().data());

                    // Copy the label
                    hash.second = item.second;

                    // Set result
                    oprf_hashes[idx].first = hash.first;
                    oprf_hashes[idx].second = EncryptedLabel(move(hash.second), allocator<unsigned char>());
                }
            };

            for (size_t thread_idx = 0; thread_idx < ThreadPoolMgr::get_thread_count();
                 thread_idx++) {
                futures[thread_idx] = tpm.thread_pool().enqueue(
                    ComputeHashesLambda, thread_idx, ThreadPoolMgr::get_thread_count());
            }

            for (auto &f : futures) {
                f.get();
            }

            return oprf_hashes;
        }
    } // namespace oprf
} // namespace apsi
