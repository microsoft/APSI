// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/oprf/oprf_receiver.h"

// SEAL
#include "seal/util/defines.h"

using namespace std;
using namespace seal;

namespace apsi
{
    namespace oprf
    {
        void OPRFReceiver::set_item_count(std::size_t item_count)
        {
            auto new_pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);
            oprf_queries_ = DynArray<seal_byte>(item_count * oprf_query_size, new_pool);
            inv_factor_data_ = FactorData(new_pool, item_count);
            pool_ = move(new_pool);
        }

        void OPRFReceiver::clear()
        {
            set_item_count(0);
        }

        vector<seal_byte> OPRFReceiver::query_data() const
        {
            return { oprf_queries_.cbegin(), oprf_queries_.cend() };
        }

        void OPRFReceiver::process_items(gsl::span<const oprf_item_type> oprf_items)
        {
            set_item_count(oprf_items.size());

            auto oprf_out_ptr = oprf_queries_.begin();
            for (size_t i = 0; i < item_count(); i++)
            {
                // Create an elliptic curve point from the item
                ECPoint ecpt({ reinterpret_cast<const unsigned char *>(oprf_items[i].data()), oprf_item_size });

                // Create a random scalar for OPRF and save its inverse
                ECPoint::scalar_type random_scalar;
                ECPoint::make_random_nonzero_scalar(random_scalar);
                ECPoint::invert_scalar(random_scalar, inv_factor_data_.get_factor(i));

                // Multiply our point with the random scalar
                ecpt.scalar_multiply(random_scalar, false);

                // Save the result to items_buffer
                ecpt.save(ECPoint::point_save_span_type{ reinterpret_cast<unsigned char *>(oprf_out_ptr), oprf_query_size });

                // Move forward
                advance(oprf_out_ptr, oprf_query_size);
            }
        }

        void OPRFReceiver::process_responses(
            gsl::span<const seal_byte> oprf_responses,
            gsl::span<oprf_hash_type> oprf_hashes) const
        {
            if (oprf_hashes.size() != item_count())
            {
                throw invalid_argument("oprf_hashes has invalid size");
            }
            if (oprf_responses.size() != item_count() * oprf_response_size)
            {
                throw invalid_argument("oprf_responses size is incompatible with oprf_hashes size");
            }

            auto oprf_in_ptr = oprf_responses.data();
            for (size_t i = 0; i < item_count(); i++)
            {
                // Load the point from items_buffer
                ECPoint ecpt;
                ecpt.load(
                    ECPoint::point_save_span_const_type{ reinterpret_cast<const unsigned char *>(oprf_in_ptr), oprf_response_size });

                // Multiply with inverse random scalar
                ecpt.scalar_multiply(inv_factor_data_.get_factor(i), false);

                // Write the hash to the appropriate item
                ecpt.extract_hash(ECPoint::hash_span_type{ reinterpret_cast<unsigned char *>(oprf_hashes[i].data()), ECPoint::hash_size });

                // Move forward
                advance(oprf_in_ptr, oprf_response_size);
            }
        }
    } // namespace oprf
} // namespace apsi
