// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

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
                stream.write(
                    reinterpret_cast<const char*>(oprf_key_.cbegin()),
                    oprf_key_size);
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
                stream.read(
                    reinterpret_cast<char*>(oprf_key_.begin()),
                    oprf_key_size);
            }
            catch (const ios_base::failure &)
            {
                stream.exceptions(old_except_mask);
                throw runtime_error("I/O error");
            }
            stream.exceptions(old_except_mask);
        }

        void OPRFSender::ProcessQueries(
            gsl::span<const unsigned char, gsl::dynamic_extent> oprf_queries,
            const OPRFKey &oprf_key,
            gsl::span<unsigned char, gsl::dynamic_extent> oprf_responses)
        {
            if (static_cast<size_t>(oprf_queries.size()) != oprf_responses.size())
            {
                throw invalid_argument("oprf_queries size is incompatible with oprf_responses size");
            }
            if (static_cast<size_t>(oprf_queries.size()) % oprf_query_size)
            {
                throw invalid_argument("oprf_queries has invalid size");
            }

            size_t query_count =
                static_cast<size_t>(oprf_queries.size()) / oprf_query_size;

            auto oprf_in_ptr = oprf_queries.data();
            auto oprf_out_ptr = oprf_responses.data();

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
            gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items,
            const OPRFKey &oprf_key,
            gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes)
        {
            if (oprf_items.size() != oprf_hashes.size())
            {
                throw invalid_argument("oprf_items size is incompatible with oprf_hashes size");
            }

            // Write zero item everywhere
            fill(oprf_hashes.begin(), oprf_hashes.end(), oprf_hash_type());

            for (ptrdiff_t i = 0; i < oprf_items.size(); i++)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({
                    reinterpret_cast<const unsigned char*>(oprf_items[i].data()),
                    oprf_item_size });
                
                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span());

                // Extract the hash
                ecpt.extract_hash({
                    reinterpret_cast<unsigned char*>(oprf_hashes[i].data()),
                    ECPoint::hash_size });
            }
        }

        void OPRFSender::ComputeHashes(
            gsl::span<oprf_item_type, gsl::dynamic_extent> oprf_items,
            const OPRFKey& oprf_key)
        {
            for (ptrdiff_t i = 0; i < oprf_items.size(); i++)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({
                    reinterpret_cast<unsigned char*>(oprf_items[i].data()),
                    oprf_item_size });

                // Multiply with key
                ecpt.scalar_multiply(oprf_key.key_span());

                // Extract the hash inplace
                oprf_items[i] = oprf_item_type();
                ecpt.extract_hash({
                    reinterpret_cast<unsigned char*>(oprf_items[i].data()),
                    ECPoint::hash_size });
            }
        }
    }
}
