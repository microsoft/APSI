// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <thread>

// APSI
#include "apsi/oprf/oprf_sender.h"

using namespace std;

namespace apsi
{
    namespace oprf
    {
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
            gsl::span<const seal::SEAL_BYTE, gsl::dynamic_extent> oprf_queries, const OPRFKey &oprf_key,
            gsl::span<seal::SEAL_BYTE, gsl::dynamic_extent> oprf_responses)
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
                ecpt.load({ oprf_in_ptr, oprf_query_size });

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span());

                // Save the result to oprf_responses
                ecpt.save({ oprf_out_ptr, oprf_response_size });

                // Move forward
                advance(oprf_in_ptr, oprf_query_size);
                advance(oprf_out_ptr, oprf_response_size);
            }
        }

        void OPRFSender::ComputeHashes(
            gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items, const OPRFKey &oprf_key,
            gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes, const int threads)
        {
            if (oprf_items.size() != oprf_hashes.size())
            {
                throw invalid_argument("oprf_items size is incompatible with oprf_hashes size");
            }

            size_t thread_count =
                threads < 1 ? static_cast<size_t>(thread::hardware_concurrency()) : static_cast<size_t>(threads);

            vector<thread> thrds;
            for (size_t t = 0; t < thread_count; t++)
            {
                thrds.emplace_back([&](size_t idx) {
                    compute_hashes_worker(idx, thread_count, oprf_items, oprf_key, oprf_hashes); }, t);
            }

            for (auto &t : thrds)
            {
                t.join();
            }
        }

        void OPRFSender::compute_hashes_worker(
            const size_t thread_idx, const size_t threads,
            gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items, const OPRFKey &oprf_key,
            gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes)
        {
            for (size_t i = thread_idx; i < oprf_items.size(); i += threads)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({ reinterpret_cast<const unsigned char *>(oprf_items[i].data()), oprf_item_size });

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span());

                // Extract the hash
                ecpt.extract_hash({ reinterpret_cast<unsigned char *>(oprf_hashes[i].data()), ECPoint::hash_size });
            }
        }
    } // namespace oprf
} // namespace apsi
