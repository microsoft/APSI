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

using namespace std;
using namespace seal;

namespace {
    auto ComputeHashesUnlabeled = [](const gsl::span<const apsi::oprf::oprf_item_type> &items,
                                     apsi::oprf::OPRFKey &oprf_key,
                                     size_t start_idx,
                                     size_t step,
                                     vector<apsi::oprf::oprf_hash_type> &result) {
        for (size_t idx = start_idx; idx < items.size(); idx += step) {
            const apsi::oprf::oprf_item_type &item = items[idx];

            // Create an elliptic curve point from the item
            apsi::oprf::ECPoint ecpt(item.get_as<const unsigned char>());

            // Multiply with key
            ecpt.scalar_multiply(oprf_key.key_span(), true);

            // Extract the item hash and the label encryption key
            array<unsigned char, apsi::oprf::ECPoint::hash_size> item_hash_and_label_key;
            ecpt.extract_hash(item_hash_and_label_key);

            // The first 128 bits represent the item hash; the next 128 bits represent the label
            // encryption key and are discarded in this overload of ComputeHashes
            apsi::oprf::oprf_hash_type hash;
            copy_n(
                item_hash_and_label_key.data(),
                apsi::oprf::oprf_hash_size,
                hash.get_as<unsigned char>().data());

            // Set result
            result[idx] = hash;
        }
    };

    auto ComputeHashesLabeled =
        [](const gsl::span<const pair<apsi::oprf::oprf_item_type, apsi::util::FullWidthLabel>>
               &items,
           const apsi::oprf::OPRFKey &oprf_key,
           size_t start_idx,
           size_t step,
           vector<pair<apsi::oprf::oprf_hash_type, apsi::util::FullWidthLabel>> &result) {
            for (size_t idx = start_idx; idx < items.size(); idx += step) {
                const pair<apsi::oprf::oprf_item_type, apsi::util::FullWidthLabel> &item =
                    items[idx];

                // Create an elliptic curve point from the item
                apsi::oprf::ECPoint ecpt(item.first.get_as<const unsigned char>());

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span(), true);

                // Extract the item hash and the label encryption key
                array<unsigned char, apsi::oprf::ECPoint::hash_size> item_hash_and_label_key;
                ecpt.extract_hash(item_hash_and_label_key);

                // The first 128 bits represent the item hash; the next 128 bits represent the label
                // encryption key
                pair<apsi::oprf::oprf_hash_type, apsi::util::FullWidthLabel> hash;
                copy_n(
                    item_hash_and_label_key.data(),
                    apsi::oprf::oprf_hash_size,
                    hash.first.get_as<unsigned char>().data());

                // Copy the label
                hash.second = item.second;

                // Set result
                result[idx] = hash;
            }
        };
} // namespace

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
            const gsl::span<const oprf_item_type> &oprf_items,
            const OPRFKey &oprf_key,
            size_t threads)
        {
            if (0 == threads) {
                threads = thread::hardware_concurrency();
            }

            vector<oprf_hash_type> oprf_hashes(oprf_items.size());
            vector<future<void>> futures(threads);

            for (size_t thread_idx = 0; thread_idx < threads; thread_idx++) {
                futures[thread_idx] = async(
                    std::launch::async,
                    ComputeHashesUnlabeled,
                    oprf_items,
                    oprf_key,
                    thread_idx,
                    threads,
                    oprf_hashes);
            }

            for (auto &f : futures) {
                f.get();
            }

            return oprf_hashes;
        }

        vector<pair<oprf_hash_type, FullWidthLabel>> OPRFSender::ComputeHashes(
            const gsl::span<const pair<oprf_item_type, FullWidthLabel>> &oprf_item_labels,
            const OPRFKey &oprf_key,
            size_t threads)
        {
            if (0 == threads) {
                threads = thread::hardware_concurrency();
            }

            vector<pair<oprf_hash_type, FullWidthLabel>> oprf_hashes(oprf_item_labels.size());
            vector<future<void>> futures(threads);

            for (size_t thread_idx = 0; thread_idx < threads; thread_idx++) {
                futures[thread_idx] = async(
                    std::launch::async,
                    ComputeHashesLabeled,
                    oprf_item_labels,
                    oprf_key,
                    thread_idx,
                    threads,
                    oprf_hashes);
            }

            for (auto &f : futures) {
                f.get();
            }

            return oprf_hashes;
        }
    } // namespace oprf
} // namespace apsi
