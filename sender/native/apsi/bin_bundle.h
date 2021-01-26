// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <vector>
#include <cstddef>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/bloom_filter.h"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/iterator.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarithsmallmod.h"

using namespace apsi::util;

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
        struct BatchedPlaintextPolyn
        {
            /**
            A sequence of coefficients represented as batched plaintexts. The length of this vector is the degree of the
            highest-degree polynomial in the sequence.
            */
            std::vector<std::vector<seal::seal_byte>> batched_coeffs;

            /**
            We need this to compute eval()
            */
            CryptoContext crypto_context;

            BatchedPlaintextPolyn(const BatchedPlaintextPolyn &copy) = delete;

            BatchedPlaintextPolyn(BatchedPlaintextPolyn &&source) = default;

            BatchedPlaintextPolyn &operator=(const BatchedPlaintextPolyn &assign) = delete;

            BatchedPlaintextPolyn &operator=(BatchedPlaintextPolyn &&assign) = default;

            /**
            Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator and batch encoder
            to do encoding and NTT ops.
            */
            BatchedPlaintextPolyn(
                const std::vector<FEltPolyn> &polyns,
                CryptoContext crypto_context,
                bool compressed
            );

            /**
            Constructs an uninitialized Plaintext polynomial using the given crypto context
            */
            BatchedPlaintextPolyn(CryptoContext crypto_context) :
                crypto_context(std::move(crypto_context))
            {}

            /**
            Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input ciphertext C
            ourselves. Instead we assume they've been precomputed and accept the powers: (C, C², C³, ...) as input.
            The number of powers provided MUST be equal to plaintext_polyn_coeffs_.size()-1.
            */
            seal::Ciphertext eval(const std::vector<seal::Ciphertext> &ciphertext_powers) const;

            /**
            Returns whether this polynomial has non-zero size.
            */
            explicit operator bool() const noexcept
            {
                return batched_coeffs.size();
            }
        };

        // A cache of all the polynomial and plaintext computations on a single BinBundle
        struct BinBundleCache
        {
            BinBundleCache(const BinBundleCache &copy) = delete;

            BinBundleCache(BinBundleCache &&source) = default;

            BinBundleCache &operator=(const BinBundleCache &assign) = delete;

            BinBundleCache &operator=(BinBundleCache &&assign) = default;

            BinBundleCache(const CryptoContext &crypto_context) :
                batched_matching_polyn(crypto_context),
                batched_interp_polyn(crypto_context)
            {}

            /**
            For each bin, stores the "matching polynomial", i.e., unique monic polynomial whose roots are precisely
            the items in the bin.
            */
            std::vector<FEltPolyn> felt_matching_polyns;

            /**
            For each bin, stores the Newton intepolation polynomial whose value at each item in the bin equals the
            item's corresponding label. Note that this field is empty when doing unlabeled PSI.
            */
            std::vector<FEltPolyn> felt_interp_polyns;

            /**
            Cached seal::Plaintext representation of the "matching" polynomial of this BinBundle.
            */
            BatchedPlaintextPolyn batched_matching_polyn;

            /**
            Cached seal::Plaintext representation of the interpolation polynomial of this BinBundle. Note that this
            field is empty when doing unlabeled PSI.
            */
            BatchedPlaintextPolyn batched_interp_polyn;
        }; // struct BinBundleCache

        /**
        Represents a specific bin bundle and stores the associated data. The type parameter L represents the label type.
        This is either a field element (in the case of labeled PSI), or an element of the unit type (in the case of
        unlabeled PSI).
        */
        template<typename L>
        class BinBundle
        {
        private:
            /**
            This is true iff cache_ needs to be regenerated
            */
            bool cache_invalid_;

            /**
            We need this to make Plaintexts
            */
            CryptoContext crypto_context_;

            /**
            The bins of the BinBundle. Each bin is a key-value store, where the keys are (chunks of the OPRF'd) DB
            items and the labels are either field elements or empty (a unit type).
            */
            std::vector<std::vector<std::pair<felt_t, L>>> bins_;

            /**
            Each bin in the BinBundle has a BloomFilter that helps quickly determine whether a field element is
            contained.
            */
            std::vector<apsi::sender::util::BloomFilter> filters_;

            /**
            A cache of all the computations we can do on the bins. This is empty by default.
            */
            BinBundleCache cache_;

            /**
            Indicates whether SEAL plaintexts are compressed in memory.
            */
            bool compressed_;

            /**
            Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is just the "matching"
            polynomial. For labeled PSI, this is the "matching" polynomial and the Newton interpolation polynomial.
            Resulting values are stored in cache_.
            */
            void regen_polyns();

            /**
            Batches this BinBundle's polynomials into SEAL Plaintexts. Resulting values are stored in cache_.
            */
            void regen_plaintexts();

            /**
            Maximum size of the bins
            */
            std::size_t max_bin_size_;

            /**
            Returns the modulus that defines the finite field that we're working in
            */
            const seal::Modulus &field_mod() const;

        public:
            BinBundle(const CryptoContext &crypto_context, bool compressed, std::size_t max_bin_size);

            BinBundle(const BinBundle &copy) = delete;

            BinBundle(BinBundle &&source) = default;

            BinBundle &operator=(const BinBundle &assign) = delete;

            BinBundle &operator=(BinBundle &&assign) = default;

            /**
            Does a dry-run insertion of item-label pairs into sequential bins, beginning at start_bin_idx. This does not
            mutate the BinBundle. On success, returns the size of the largest bin bins in the modified range, after
            insertion has taken place. On failed insertion, returns -1.
            */
            int multi_insert_dry_run(
                const std::vector<std::pair<felt_t, L>> &item_label_pairs,
                std::size_t start_bin_idx
            );

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx. On success, returns the size of
            the largest bin bins in the modified range, after insertion has taken place. On failed insertion, returns
            -1. On failure, no modification is made to the BinBundle.
            */
            int multi_insert_for_real(
                const std::vector<std::pair<felt_t, L>> &item_label_pairs,
                std::size_t start_bin_idx
            );

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is specified, no
            change is made to the BinBundle. On success, returns the size of the largest bin bins in the modified range,
            after insertion has taken place. On failed insertion, returns -1. On failure, no modification is made to the
            BinBundle.
            */
            int multi_insert(
                const std::vector<std::pair<felt_t, L>> &item_label_pairs,
                std::size_t start_bin_idx,
                bool dry_run
            );

            /**
            Attempts to overwrite the stored items' labels with the given labels. Returns true iff it found a contiguous
            sequence of given items. If no such sequence was found, this BinBundle is not mutated. This function can be
            called on a BinBundle<monostate> but it won't do anything except force the cache to get recomputed, so don't
            bother.
            */
            bool try_multi_overwrite(
                const std::vector<std::pair<felt_t, L>> &item_label_pairs,
                std::size_t start_bin_idx
            );

            /**
            Attempts to remove the stored items and labels. Returns true iff it found a contiguous sequence of given
            items and the data was successfully removed. If no such sequence was found, this BinBundle is not mutated.
            */
            bool try_multi_remove(
                const std::vector<felt_t> &items,
                std::size_t start_bin_idx
            );

            /**
            Sets the given labels to the set of labels associated with the sequence of items in this BinBundle, starting
            at start_idx. If any item is not present in its respective bin, this returns false and clears the given
            labels vector. Returns true on success.
            */
            bool try_get_multi_label(
                const std::vector<felt_t> &items,
                std::size_t start_bin_idx,
                std::vector<L> &labels
            ) const;

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
            bool cache_invalid() const;

            /**
            Gets a constant reference to this BinBundle's cache. This will throw an exception if the cache is invalid.
            Check the cache before you wreck the cache.
            */
            const BinBundleCache &get_cache() const;

            /**
            Generates and caches all the polynomials and plaintexts that this BinBundle requires
            */
            void regen_cache();

            /**
            Returns a constant reference to the vector of bins in this BinBundle.
            */
            const std::vector<std::map<felt_t, L>> &get_bins() const
            {
                return bins_;
            }

            /**
            Returns whether this BinBundle is empty.
            */
            bool empty() const;

            /**
            Saves the BinBundle to a stream.
            */
            std::size_t save(std::ostream &out, std::uint32_t bundle_idx) const;

            /**
            Loads the BinBundle from a stream.
            */
            std::pair<std::uint32_t, std::size_t> load(std::istream &in);
        }; // class BinBundle
    } // namespace sender
} // namespace apsi
