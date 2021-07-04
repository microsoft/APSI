// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>

// APSI
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"

using namespace std;
using namespace seal;

namespace apsi {
    using namespace util;

    namespace oprf {
        void OPRFReceiver::set_item_count(std::size_t item_count)
        {
            auto new_pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);
            oprf_queries_ = DynArray<unsigned char>(item_count * oprf_query_size, new_pool);
            inv_factor_data_ = FactorData(new_pool, item_count);
            pool_ = move(new_pool);
        }

        void OPRFReceiver::clear()
        {
            set_item_count(0);
        }

        vector<unsigned char> OPRFReceiver::query_data() const
        {
            return { oprf_queries_.cbegin(), oprf_queries_.cend() };
        }

        void OPRFReceiver::process_items(gsl::span<const Item> oprf_items)
        {
            set_item_count(oprf_items.size());

            auto oprf_out_ptr = oprf_queries_.begin();
            for (size_t i = 0; i < item_count(); i++) {
                // Create an elliptic curve point from the item
                ECPoint ecpt(oprf_items[i].get_as<const unsigned char>());

                // Create a random scalar for OPRF and save its inverse
                ECPoint::scalar_type random_scalar;
                ECPoint::MakeRandomNonzeroScalar(random_scalar);
                ECPoint::InvertScalar(random_scalar, inv_factor_data_.get_factor(i));

                // Multiply our point with the random scalar
                ecpt.scalar_multiply(random_scalar, false);

                // Save the result to items_buffer
                ecpt.save(ECPoint::point_save_span_type{ oprf_out_ptr, oprf_query_size });

                // Move forward
                advance(oprf_out_ptr, oprf_query_size);
            }
        }

        void OPRFReceiver::process_responses(
            gsl::span<const unsigned char> oprf_responses,
            gsl::span<HashedItem> oprf_hashes,
            gsl::span<LabelKey> label_keys) const
        {
            if (oprf_hashes.size() != item_count()) {
                throw invalid_argument("oprf_hashes has invalid size");
            }
            if (label_keys.size() != item_count()) {
                throw invalid_argument("label_keys has invalid size");
            }
            if (oprf_responses.size() != item_count() * oprf_response_size) {
                throw invalid_argument("oprf_responses size is incompatible with oprf_hashes size");
            }

            auto oprf_in_ptr = oprf_responses.data();
            for (size_t i = 0; i < item_count(); i++) {
                // Load the point from items_buffer
                ECPoint ecpt;
                ecpt.load(ECPoint::point_save_span_const_type{ oprf_in_ptr, oprf_response_size });

                // Multiply with inverse random scalar
                ecpt.scalar_multiply(inv_factor_data_.get_factor(i), false);

                // Extract the item hash and the label encryption key
                array<unsigned char, ECPoint::hash_size> item_hash_and_label_key;
                ecpt.extract_hash(item_hash_and_label_key);

                // The first 16 bytes represent the item hash; the next 32 bytes represent the label
                // encryption key
                copy_bytes(
                    item_hash_and_label_key.data(), oprf_hash_size, oprf_hashes[i].value().data());
                copy_bytes(
                    item_hash_and_label_key.data() + oprf_hash_size,
                    label_key_byte_count,
                    label_keys[i].data());

                // Move forward
                advance(oprf_in_ptr, oprf_response_size);
            }
        }
    } // namespace oprf
} // namespace apsi
