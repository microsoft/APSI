// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <thread>

// APSI
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"

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

        unordered_set<oprf_hash_type> OPRFSender::ComputeHashes(
            const unordered_set<oprf_item_type> &oprf_items,
            const OPRFKey &oprf_key)
        {
            unordered_set<oprf_hash_type> oprf_hashes;

            for (auto &item : oprf_items)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt(item.get_as<const unsigned char>());

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span(), true);

                // Extract the item hash and the label encryption key
                array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
                ecpt.extract_hash(item_hash_and_label_key);

                // The first 128 bits represent the item hash; the next 128 bits represent the label encryption key and
                // are discarded in this overload of ComputeHashes
                oprf_hash_type hash;
                copy_n(item_hash_and_label_key.data(), oprf_hash_size, hash.get_as<unsigned char>().data());

                // Add to result
                oprf_hashes.insert(move(hash));
            }

            return oprf_hashes;
        }

        unordered_map<oprf_hash_type, EncryptedLabel> OPRFSender::ComputeHashes(
            const unordered_map<oprf_item_type, Label> &oprf_item_labels,
            const OPRFKey &oprf_key)
        {
            unordered_map<oprf_hash_type, EncryptedLabel> oprf_hashes;

            for (auto &item_label_pair : oprf_item_labels)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt(item_label_pair.first.get_as<const unsigned char>());

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span(), true);

                // Extract the item hash and the label encryption key
                array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
                ecpt.extract_hash(item_hash_and_label_key);

                // The first 128 bits represent the item hash; the next 128 bits represent the label encryption key
                pair<oprf_hash_type, EncryptedLabel> hash;
                copy_n(item_hash_and_label_key.data(), oprf_hash_size, hash.first.get_as<unsigned char>().data());

                // Copy the label
                hash.second = EncryptedLabel(item_label_pair.second, allocator<unsigned char>());

                // Add to result
                oprf_hashes.insert(move(hash));
            }

            return oprf_hashes;
        }
    } // namespace oprf
} // namespace apsi
