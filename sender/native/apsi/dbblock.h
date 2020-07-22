// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <vector>
#include <cstddef>

// APSI
#include "apsi/item.h"

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/plaintext.h"
#include "seal/batchencoder.h"

namespace apsi
{
    namespace sender
    {
        struct monostate {};

        // A cache of all the polynomial computations on a single bin
        struct BinPolynCache
        {
            /** The highest-degree divided differences computed so far. For unlabeled PSI, this is empty
            NOTE: This is not enabled yet. Caching the divided differences would allow us to add items to a BinBundle
            without having to recalculate the whole polynomial
            */
            //std::vector<felt_t> divided_diffs;

            /**
            For unlabeled PSI, this is the unique monic polynomial whose roots are precisely the items in the bin. For
            labeled PSI, this the Newton intepolation polynomial whose value at each item in the bin equals the item's
            corresponding label.
            */
            std::vector<felt_t> interpolation_polyn_coeffs;
        }; // struct BinPolynCache

        // A cache of all the polynomial and plaintext computations on a single BinBundle
        struct BinBundleCache
        {
            /**
            Cached polynomial computations for each bin
            */
            std::vector<BinPolynCache> bin_polyns_;

            /**
            The interpolation polynomial represented as batched plaintexts. The length of this vector is the degree of
            the highest-degree polynomial in polyn_cache_, i.e., the size of the largest bin.
            */
            std::vector<seal::Plaintext> plaintext_polyn_coeffs_;
        }; // struct BinBundleCache

        /**
        Represents a specific batch/split and stores the associated data. The type parameter L represents the label
        type. This is either a field element (in the case of labeled PSI), or an element of the unit type (in the case
        of unlabeled PSI)
        */
        template<typename L>
        class BinBundle
        {
        private:

            /**
            The bins of the BinBundle. Each bin is a key-value store, where the keys are (chunks of the OPRF'd) DB
            items and the labels are either field elements or empty (a unit type).
            */
            std::vector<std::map<felt_t, L>> bins_;

            /**
            A cache of all the computations we can do on the bins. This is empty by default
            */
            BinBundleCache cache_;

            /**
            This is true iff cache_ needs to be regenerated
            */
            bool cache_invalid_;

            /**
            The modulus that defines our field
            */
            seal::Modulus mod_;

            /**
            Stuff we need to make Plaintexts
            */
            std::shared_ptr<seal::SEALContext> seal_ctx_;
            std::shared_ptr<seal::Evaluator> evaluator_;
            std::shared_ptr<seal::BatchEncoder> batch_encoder_;

            /**
            Computes the appropriate polynomial for each bin. Stores the result in cache_.
            For unlabeled PSI, this is the unique monic polynomial whose roots are precisely the items in the bin.
            For labeled PSI, this the Newton inteprolation polynomial whose value at each item in the bin equals the
            item's corresponding label.
            */
            void regen_polyns();

            /**
            Computes and caches the bin's polynomial coeffs in Plaintexts
            */
            void regen_plaintexts();

        public:
            BinBundle(
                std::size_t num_bins,
                std::shared_ptr<seal::SEALContext> seal_ctx,
                std::shared_ptr<seal::Evaluator> evaluator,
                std::shared_ptr<seal::BatchEncoder> batch_encoder,
                seal::Modulus mod
            );

            ~BinBundle();

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx.
            Returns true on success. Returns false if any pair failed insertion. If false, no modification is made to
            the BinBundle.
            */
            bool multi_insert(std::vector<std::pair<felt_t, L>> item_label_pairs, std::size_t start_bin_idx);

            /**
            Clears the contents of the BinBundle and wipes out the cache
            */
            void clear();

            /**
            Wipes out the cache of the BinBundle
            */
            void clear_cache();

            /**
            Generates and caches the polynomials and plaintexts that represent the BinBundle
            */
            void regen_cache();

        }; // class BinBundle
    } // namespace sender
} // namespace apsi
