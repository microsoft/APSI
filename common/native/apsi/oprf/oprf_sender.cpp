// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <thread>
#include <algorithm>

// GSL
#include <gsl/span_ext>

// APSI
#include "apsi/oprf/oprf_sender.h"
#include "apsi/util/utils.h"

using namespace std;

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

        void OPRFSender::ProcessQueries(
            gsl::span<const seal::seal_byte> oprf_queries, const OPRFKey &oprf_key,
            gsl::span<seal::seal_byte> oprf_responses)
        {
            if (oprf_queries.size() != oprf_responses.size())
            {
                throw invalid_argument("oprf_queries size is incompatible with oprf_responses size");
            }
            if (static_cast<size_t>(oprf_queries.size()) % oprf_query_size)
            {
                throw invalid_argument("oprf_queries has invalid size");
            }

            size_t query_count = static_cast<size_t>(oprf_queries.size()) / oprf_query_size;

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
        }

        unordered_set<oprf_hash_type> OPRFSender::ComputeHashes(
            const unordered_set<oprf_item_type> &oprf_items,
            const OPRFKey &oprf_key)
        {
            unordered_set<oprf_hash_type> oprf_hashes;

            for (auto &item : oprf_items)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({ reinterpret_cast<const unsigned char *>(item.data()), oprf_item_size });

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span(), true);

                // Extract the hash
                oprf_hash_type hash;
                ecpt.extract_hash(ECPoint::hash_span_type{ reinterpret_cast<unsigned char *>(hash.data()), ECPoint::hash_size });

                // Add to result
                oprf_hashes.insert(move(hash));
            }

            return oprf_hashes;
        }

        unordered_map<oprf_hash_type, FullWidthLabel> OPRFSender::ComputeHashes(
            const unordered_map<oprf_item_type, FullWidthLabel> &oprf_item_labels,
            const OPRFKey &oprf_key)
        {
            unordered_map<oprf_hash_type, FullWidthLabel> oprf_hashes;

            for (auto &item_label_pair : oprf_item_labels)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({ reinterpret_cast<const unsigned char *>(item_label_pair.first.data()), oprf_item_size });

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span(), true);

                // Extract the hash
                pair<oprf_hash_type, FullWidthLabel> hash;
                ecpt.extract_hash(ECPoint::hash_span_type{ reinterpret_cast<unsigned char *>(hash.first.data()), ECPoint::hash_size });

                // Copy the label
                hash.second = item_label_pair.second;

                // Add to result
                oprf_hashes.insert(move(hash));
            }

            return oprf_hashes;
        }
    } // namespace oprf
} // namespace apsi
