// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/oprf/oprf_receiver.h"

using namespace std;

namespace apsi
{
    namespace oprf
    {
        void OPRFReceiver::process_items(
            gsl::span<const oprf_item_type> oprf_items,
            gsl::span<seal::SEAL_BYTE> oprf_queries)
        {
            if (static_cast<size_t>(oprf_queries.size()) != static_cast<size_t>(oprf_items.size()) * oprf_query_size)
            {
                throw invalid_argument("oprf_queries size is incompatible with oprf_items size");
            }

            set_item_count(static_cast<size_t>(oprf_items.size()));

            auto oprf_out_ptr = reinterpret_cast<unsigned char *>(oprf_queries.data());
            for (size_t i = 0; i < item_count(); i++)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({ reinterpret_cast<const unsigned char *>(oprf_items[i].data()), oprf_item_size });

                // Create a random scalar for OPRF and save its inverse
                ECPoint::scalar_type random_scalar;
                ECPoint::make_random_nonzero_scalar(random_scalar);
                ECPoint::invert_scalar(random_scalar, inv_factor_data_.get_factor(i));

                // Multiply our point with the random scalar
                ecpt.scalar_multiply(random_scalar);

                // Save the result to items_buffer
                ecpt.save({ oprf_out_ptr, oprf_query_size });

                // Move forward
                advance(oprf_out_ptr, oprf_query_size);
            }
        }

        void OPRFReceiver::process_responses(
            gsl::span<const seal::SEAL_BYTE> oprf_responses,
            gsl::span<oprf_hash_type> oprf_hashes) const
        {
            if (static_cast<size_t>(oprf_hashes.size()) != item_count())
            {
                throw invalid_argument("oprf_hashes has invalid size");
            }
            if (static_cast<size_t>(oprf_responses.size()) != item_count() * oprf_response_size)
            {
                throw invalid_argument("oprf_responses size is incompatible with oprf_hashes size");
            }

            auto oprf_in_ptr = reinterpret_cast<const unsigned char *>(oprf_responses.data());

            for (size_t i = 0; i < item_count(); i++)
            {
                // Load the point from items_buffer
                ECPoint ecpt;
                ecpt.load({ oprf_in_ptr, oprf_response_size });

                // Multiply with inverse random scalar
                ecpt.scalar_multiply(inv_factor_data_.get_factor(i));

                // Write the hash to the appropriate item
                ecpt.extract_hash({ reinterpret_cast<unsigned char *>(oprf_hashes[i].data()), ECPoint::hash_size });

                // Move forward
                advance(oprf_in_ptr, oprf_response_size);
            }
        }
    } // namespace oprf
} // namespace apsi
