// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <vector>
#include <cstddef>

// APSI
#include "apsi/item.h"
#include "apsi/sendersessioncontext.h" 

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/plaintext.h"
#include "seal/batchencoder.h"

namespace apsi
{
    namespace sender
    {
        /**
        Represents a polynomial with coefficients that are field elements. Coefficients are stored in degree-increasing
        order, so, for example, the constant term is at index 0.
        */
        using FEltPolyn = std::vector<felt_t>;

        /**
        A bunch of polynomials represented using a sequence of batched SEAL Plaintexts.

        Example: Suppose we have 3 polynomials,

            3x⁵ + 7x⁴ +  x³ + 9x² + 4x + 2
                        8x³ + 5x² +    + 1
                  9x⁴ + 2x³ +     +  x + 8

        To represent them as a BatchedPlaintextPolyn, we would make a Plaintext for every column of coefficients.
        Suppose each Plaintext has 3 slots. Let Plaintext #i holds all the coefficients of degree i. So then the
        plaintexts P₀, ..., P₅ would be

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
            Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator and batch encoder
            to do encoding and NTT ops.
            */
            BatchedPlaintextPolyn(
                std::vector<FEltPolyn> polyns,
                std::shared_ptr<seal::Evaluator> evaluator,
                std::shared_ptr<seal::BatchEncoder> batch_encoder
            );

            /**
            Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input ciphertext C
            ourselves. Instead we assume they've been precomputed and accept the powers: (C, C², C³, ...) as input.
            The number of powers provided MUST be equal to plaintext_polyn_coeffs_.size()-1.
            */
            seal::Ciphertext eval(const std::vector<seal::Ciphertext> &ciphertext_powers) const;

            /**
            Returns whether this polynomial has size at least 2. This is necessary for the eval function to work.
            */
            explicit operator bool() const noexcept
            {
                return batched_coeffs_.size() >= 2;
            }
        };

        // A cache of all the polynomial and plaintext computations on a single BinBundle
        struct BinBundleCache
        {
            /**
            For each bin, stores the "matching polynomial", i.e., unique monic polynomial whose roots are precisely the
            items in the bin
            */
            std::vector<FEltPolyn> felt_matching_polyns;

            /**
            For each bin, stores the Newton intepolation polynomial whose value at each item in the bin equals the
            item's corresponding label. Note that this field is empty when doing unlabeled PSI.
            */
            std::vector<FEltPolyn> felt_interp_polyns;

            /**
            Cached seal::Plaintext representation of the "matching" polynomial of this BinBundle
            */
            BatchedPlaintextPolyn batched_matching_polyn;

            /**
            Cached seal::Plaintext representation of the interpolation polynomial of this BinBundle. Note that this
            field is empty when doing unlabeled PSI.
            */
            BatchedPlaintextPolyn batched_interp_polyn;
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
            Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is just the "matching"
            polynomial. For labeled PSI, this is the "matching" polynomial and the Newton interpolation polynomial.
            Resulting values are stored in cache_.
            */
            virtual void regen_polyns();

            /**
            Batches this BinBundle's polynomials into SEAL Plaintexts. Resulting values are stored in cache_.
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
            Returns whether this BinBundle's cache needs to be recomputed
            */
            bool cache_invalid();

            /**
            Gets an immutable reference to this BinBundle's cache. This will throw an exception if the cache is invalid.
            Check the cache before you wreck the cache.
            */
            const BinBundleCache& get_cache();

            /**
            Generates and caches all the polynomials and plaintexts that this BinBundle requires
            */
            void regen_cache();

        }; // class BinBundle

        /**
        An UnlabeledBinBundle is a BinBundle<L> where L (the label type) is the unit type
        */
        class UnlabeledBinBundle: public BinBundle<monostate>
        {
        private:
            /**
            Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is just the "matching"
            polynomial. Resulting values are stored in cache_.
            */
            void regen_polyns();
        }

        // A LabeledBinBundle is a BinBundle<L> where L (the label type) is felt_t
        class LabeledBinBundle: public BinBundle<felt_t>
        {
        private:
            /**
            Computes and caches the appropriate polynomials of each bin. For labeled PSI, this is the "matching"
            polynomial and the Newton interpolation polynomial. Resulting values are stored in cache_.
            */
            void regen_polyns();
        }

    } // namespace sender
} // namespace apsi
