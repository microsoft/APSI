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
        // A cache of all the polynomial computations on a single bin
        struct BinPolynCache
        {
            /** The highest-degree divided differences computed so far. For unlabeled PSI, this is empty
            NOTE: This is not enabled yet. Caching the divided differences would allow us to add items to a BinBundle
            without having to recalculate the whole polynomial
            */
            //std::vector<felt_t> divided_diffs;

            /**
            The Newton intepolation polynomial whose value at each item in the bin equals the item's corresponding
            label.
            */
            std::vector<felt_t> interpolation_polyn_coeffs;

            /**
            The "matching polynomial", i.e., unique monic polynomial whose roots are precisely the items in the
            bin
            */
            std::vector<felt_t> matching_polyn_coeffs;
        }; // struct BinPolynCache

        /**
        A bunch of polynomials represented using a sequence of batched SEAL Plaintexts.

        Example: Suppose we have 3 polynomials,

            3x⁵ + 7x⁴ +  x³ + 9x² + 4x + 2
                        8x³ + 5x² +    + 1
                  9x⁴ + 2x³ +     +  x + 8

        To represent them as a BatchedPlaintextPolyn, we would make a plaintext for every column of coefficients.
        Plaintext #i holds all the coefficients of degree i. So then the plaintexts P₀, ..., P₅ would be

            |P₅|P₄|P₃|P₂|P₁|P₀|
            |--|--|--|--|--|--|
            | 3| 7| 1| 9| 4| 2|
            | 0| 0| 8| 5| 0| 1|
            | 0| 9| 2| 0| 1| 8|
        */
        class BatchedPlaintextPolyn
        {
        private:
            /**
            A sequence of coefficients represented as batched plaintexts. The length of this vector is the degree of the
            highest-degree polynomial in the sequence.
            */
            std::vector<seal::Plaintext> batched_coeffs_;

        public:
            /**
            Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input ciphertext C
            ourselves. Instead we assume they've been precomputed and accept the powers: (C, C², C³, ...) as input.
            The number of powers provided MUST be equal to plaintext_polyn_coeffs_.size()-1.
            */
            seal::Ciphertext eval(const vector<Ciphertext> &ciphertext_powers);
        }

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
            virtual void regen_polyns() = 0;

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

            /**
            Does a dry-run insertion of item-label pairs into sequential bins, beginning at start_bin_idx. This does not
            mutate the BinBundle.
            On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
            On failed insertion, returns -1
            */
            int multi_insert_dry_run(
                vector<pair<felt_t, L>> &item_label_pairs,
                size_t start_bin_idx
            ) const;

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx
            On success, returns the size of the largest bin bins in the modified range, after insertion has taken place
            On failed insertion, returns -1. On failure, no modification is made to the BinBundle.
            */
            template<typename L>
            int multi_insert_for_real(
                vector<pair<felt_t, L>> item_label_pairs,
                size_t start_bin_idx
            );

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is specified, no
            change is made to the BinBundle. On success, returns the size of the largest bin bins in the modified range,
            after insertion has taken place On failed insertion, returns -1. On failure, no modification is made to the
            BinBundle.
            */
            template<typename L>
            int BinBundle<L>::multi_insert(
                vector<pair<felt_t, L>> item_label_pairs,
                size_t start_bin_idx,
                bool dry_run
            );

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

        // A LabeledBinBundle is a BinBundle<L> where L (the label type) is felt_t
        class LabeledBinBundle: public BinBundle<felt_t>
        {
        private:
            /**
            Computes the appropriate polynomial for each bin. Stores the result in cache_. For labeled PSI, this the
            Newton inteprolation polynomial whose value at each item in the bin equals the item's corresponding label.
            */
            void regen_polyns();
        }

        /**
        An UnlabeledBinBundle is a BinBundle<L> where L (the label type) is the unit type
        */
        class UnlabeledBinBundle: public BinBundle<monostate>
        {
        private:
            /**
            Computes the appropriate polynomial for each bin. Stores the result in cache_. For unlabeled PSI, this is
            the unique monic polynomial whose roots are precisely the items in the bin.
            */
            void regen_polyns();
        }
    } // namespace sender
} // namespace apsi
