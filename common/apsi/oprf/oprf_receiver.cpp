// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <stdexcept>

// APSI
#include "apsi/oprf/oprf_common.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace seal;

namespace apsi::oprf {
    using namespace apsi::util;

    void OPRFReceiver::set_item_count(std::size_t item_count)
    {
        auto new_pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);
        oprf_queries_ = DynArray<unsigned char>(item_count * oprf_query_size, new_pool);
        inv_factor_data_ = FactorData(new_pool, item_count);
        pool_ = std::move(new_pool);
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

        StackScrubGuard scrub_guard;

        auto *oprf_out_ptr = oprf_queries_.begin();
        for (size_t i = 0; i < item_count(); i++) {
            // Create an elliptic curve point from the item
            ECPoint ecpt(oprf_items[i].value());

            // Create a random scalar for OPRF and save its inverse. Wipe it however this
            // iteration ends: generating it can fail after partly filling the buffer.
            ECPoint::scalar_type random_scalar;
            SecureZeroGuard random_scalar_guard(random_scalar.data(), random_scalar.size());
            ECPoint::MakeRandomNonzeroScalar(random_scalar);
            ECPoint::InvertScalar(random_scalar, inv_factor_data_.get_factor(i));

            // Multiply our point with the random scalar
            if (!ecpt.scalar_multiply(random_scalar, false)) {
                throw logic_error("failed to blind an item");
            }

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

        StackScrubGuard scrub_guard;

        const auto *oprf_in_ptr = oprf_responses.data();
        for (size_t i = 0; i < item_count(); i++) {
            // Load the point from items_buffer
            ECPoint ecpt;
            ecpt.load(ECPoint::point_save_span_const_type{ oprf_in_ptr, oprf_response_size });

            // Check the response as it arrived, before it is used for anything.
            if (!ecpt.is_prime_order()) {
                throw runtime_error("OPRF response is not a prime-order point");
            }

            // Multiply with inverse random scalar
            if (!ecpt.scalar_multiply(inv_factor_data_.get_factor(i), false)) {
                throw runtime_error("failed to unblind an OPRF response");
            }

            // Extract the item hash and the label encryption key
            array<unsigned char, ECPoint::hash_size> item_hash_and_label_key{};
            ecpt.extract_hash(item_hash_and_label_key);

            // The first 16 bytes represent the item hash; the next 16 bytes represent the label
            // encryption key
            copy_bytes(
                item_hash_and_label_key.data(), oprf_hash_size, oprf_hashes[i].value().data());
            copy_bytes(
                item_hash_and_label_key.data() + oprf_hash_size,
                label_key_byte_count,
                label_keys[i].data());

            // Wipe the OPRF-derived secret material from the stack. The label-key half is
            // genuinely sensitive (it decrypts the per-item label ciphertexts the receiver
            // is about to receive); the hashed-item half is destined for the wire later but
            // has no reason to linger on the stack either.
            secure_zero(item_hash_and_label_key.data(), item_hash_and_label_key.size());

            // The unblinded point reproduces both, and is in this frame.
            ecpt.clear();

            // Move forward
            advance(oprf_in_ptr, oprf_response_size);
        }
    }
} // namespace apsi::oprf
