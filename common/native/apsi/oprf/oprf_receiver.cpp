// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "apsi/oprf/oprf_receiver.h"

using namespace std;

namespace apsi
{
    namespace oprf
    {
        void OPRFReceiver::process_items(
            gsl::span<const oprf_item_type, gsl::dynamic_extent> oprf_items,
            gsl::span<seal::SEAL_BYTE, gsl::dynamic_extent> oprf_queries)
        {
            if (static_cast<size_t>(oprf_queries.size()) != static_cast<size_t>(oprf_items.size()) * oprf_query_size)
            {
                throw invalid_argument("oprf_queries size is incompatible with oprf_items size");
            }

            set_item_count(static_cast<size_t>(oprf_items.size()));

            auto oprf_out_ptr = reinterpret_cast<u8 *>(oprf_queries.data());
            for (size_t i = 0; i < item_count(); i++)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt(
                    { reinterpret_cast<const u8 *>(oprf_items[static_cast<ptrdiff_t>(i)].data()), oprf_item_size });

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
            gsl::span<const seal::SEAL_BYTE, gsl::dynamic_extent> oprf_responses,
            gsl::span<oprf_hash_type, gsl::dynamic_extent> oprf_hashes) const
        {
            if (static_cast<size_t>(oprf_hashes.size()) != item_count())
            {
                throw invalid_argument("oprf_hashes has invalid size");
            }
            if (static_cast<size_t>(oprf_responses.size()) != item_count() * oprf_response_size)
            {
                throw invalid_argument("oprf_responses size is incompatible with oprf_hashes size");
            }

            // Write zero item everywhere
            fill(oprf_hashes.begin(), oprf_hashes.end(), oprf_hash_type());
            auto oprf_in_ptr = reinterpret_cast<const u8 *>(oprf_responses.data());

            for (size_t i = 0; i < item_count(); i++)
            {
                // Load the point from items_buffer
                ECPoint ecpt;
                ecpt.load({ oprf_in_ptr, oprf_response_size });

                // Multiply with inverse random scalar
                ecpt.scalar_multiply(inv_factor_data_.get_factor(i));

                // Write the hash to the appropriate item
                // Warning: the hash has size ECPoint::hash_size == 15! Thus, the
                // last u8 is not touched and must be set to zero separately.
                // This was already done earlier, but might be a performance issue
                // in some cases.
                ecpt.extract_hash({ reinterpret_cast<u8 *>(oprf_hashes[i].data()), ECPoint::hash_size });

                // Move forward
                advance(oprf_in_ptr, oprf_response_size);
            }
        }
    } // namespace oprf
} // namespace apsi
