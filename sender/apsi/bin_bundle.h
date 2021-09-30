// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <memory>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/util/cuckoo_filter.h"
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

// GSL
#include "gsl/span"

using namespace apsi::util;

namespace apsi {
    namespace sender {
        /**
        Represents a polynomial with coefficients that are field elements. Coefficients are stored
        in degree-increasing order, so, for example, the constant term is at index 0.
        */
        using FEltPolyn = std::vector<felt_t>;

        /**
        A bunch of polynomials represented using a sequence of batched SEAL Plaintexts.

        Example: Suppose we have 3 polynomials,

            3x⁵ + 7x⁴ +  x³ + 9x² + 4x + 2
                        8x³ + 5x² +    + 1
                  9x⁴ + 2x³ +     +  x + 8

        To represent them as a BatchedPlaintextPolyn, we would make a Plaintext for every column of
        coefficients. Suppose each Plaintext has 3 slots. Let Plaintext #i holds all the
        coefficients of degree i. So then the plaintexts P₀, ..., P₅ would be

            |P₅|P₄|P₃|P₂|P₁|P₀|
            |--|--|--|--|--|--|
            | 3| 7| 1| 9| 4| 2|
            | 0| 0| 8| 5| 0| 1|
            | 0| 9| 2| 0| 1| 8|
        */
        struct BatchedPlaintextPolyn {
            /**
            A sequence of coefficients represented as batched plaintexts. The length of this vector
            is the degree of the highest-degree polynomial in the sequence.
            */
            std::vector<std::vector<unsigned char>> batched_coeffs;

            /**
            We need this to compute eval()
            */
            CryptoContext crypto_context;

            BatchedPlaintextPolyn(const BatchedPlaintextPolyn &copy) = delete;

            BatchedPlaintextPolyn(BatchedPlaintextPolyn &&source) = default;

            BatchedPlaintextPolyn &operator=(const BatchedPlaintextPolyn &assign) = delete;

            BatchedPlaintextPolyn &operator=(BatchedPlaintextPolyn &&assign) = default;

            /**
            Construct and empty BatchedPlaintextPolyn instance.
            */
            BatchedPlaintextPolyn() = default;

            /**
            Constructs a batched Plaintext polynomial from a list of polynomials. Takes an evaluator
            and batch encoder to do encoding and NTT ops.
            */
            BatchedPlaintextPolyn(
                const std::vector<FEltPolyn> &polyns,
                CryptoContext context,
                std::uint32_t ps_low_degree,
                bool compressed);

            /**
            Constructs an uninitialized Plaintext polynomial using the given crypto context
            */
            BatchedPlaintextPolyn(CryptoContext context) : crypto_context(std::move(context))
            {}

            /**
            Evaluates the polynomial on the given ciphertext. We don't compute the powers of the
            input ciphertext C ourselves. Instead we assume they've been precomputed and accept the
            powers: (C, C², C³, ...) as input. The number of powers provided MUST be equal to
            plaintext_polyn_coeffs_.size()-1.
            */
            seal::Ciphertext eval(
                const std::vector<seal::Ciphertext> &ciphertext_powers,
                seal::MemoryPoolHandle &pool) const;

            /**
            Evaluates the polynomial on the given ciphertext using the Paterson-Stockmeyer
            algorithm, as long as it requires less computation than the standard evaluation function
            above. The algorithm computes h+1 inner polynomials on low powers (C¹ to C^{l-1}). Each
            inner polynomial is then multiplied by the corresponding high power. The parameters l
            and h are determined according to the degree of the polynomial and the number of splits
            in order to minimize the computation.

            Evaluated polynomial a_0 + a_1*C + a_2*C^2 + ... + C^degree

            Inner polys: a_{l*i} + a_{l*i+1}*C + ... + a_{l*i+l-1}*C^{l-1}    (for i=0,...,h-1)
                    and: a_{l*h} + a_{l*h+1}*C + ... + a_{l*h+degree%l}*C^{degree%l}  (for i=h)

            Low powers:  C^{1}, ..., C^{l-1}
            High powers: C^{1*l}, ..., C^{l*h}
            */
            seal::Ciphertext eval_patstock(
                const CryptoContext &eval_crypto_context,
                const std::vector<seal::Ciphertext> &ciphertext_powers,
                std::size_t ps_low_degree,
                seal::MemoryPoolHandle &pool) const;

            /**
            Returns whether this polynomial has non-zero size.
            */
            explicit operator bool() const noexcept
            {
                return batched_coeffs.size();
            }
        };

        // A cache of all the polynomial and plaintext computations on a single BinBundle
        struct BinBundleCache {
            BinBundleCache(const BinBundleCache &copy) = delete;

            BinBundleCache(BinBundleCache &&source) = default;

            BinBundleCache &operator=(const BinBundleCache &assign) = delete;

            BinBundleCache &operator=(BinBundleCache &&assign) = default;

            BinBundleCache(const CryptoContext &crypto_context, std::size_t label_size);

            /**
            For each bin, stores the "matching polynomial", i.e., unique monic polynomial whose
            roots are precisely the items in the bin.
            */
            std::vector<FEltPolyn> felt_matching_polyns;

            /**
            For each bin, stores the Newton intepolation polynomial whose value at each item in the
            bin equals the item's corresponding label. Note that this field is empty when doing
            unlabeled PSI.
            */
            std::vector<std::vector<FEltPolyn>> felt_interp_polyns;

            /**
            Cached seal::Plaintext representation of the "matching" polynomial of this BinBundle.
            */
            BatchedPlaintextPolyn batched_matching_polyn;

            /**
            Cached seal::Plaintext representation of the interpolation polynomial of this BinBundle.
            Note that this field is empty when doing unlabeled PSI.
            */
            std::vector<BatchedPlaintextPolyn> batched_interp_polyns;
        }; // struct BinBundleCache

        /**
        Represents a specific bin bundle and stores the associated data. The type parameter L
        represents the label type. This is either a field element (in the case of labeled PSI), or
        an element of the unit type (in the case of unlabeled PSI).
        */
        class BinBundle {
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
            Items (decomposed into field elements) for each bin in the BinBundle. The dimensions
            are, in order:
                - Bins in the BinBundle
                - Field elements in the bin
            */
            std::vector<std::vector<felt_t>> item_bins_;

            /**
            Item-size chunks of the label (decomposed into field elements) for each bin in the
            BinBundle. The dimensions are, in order:
                - Components of the label
                - Bins in the BinBundle
                - Field elements in the bin
            */
            std::vector<std::vector<std::vector<felt_t>>> label_bins_;

            /**
            Each bin in the BinBundle has a CuckooFilter that helps quickly determine whether a
            field element is contained.
            */
            std::vector<util::CuckooFilter> filters_;

            /**
            Indicates whether SEAL plaintexts are compressed in memory.
            */
            bool compressed_;

            /**
            Indicates whether the BinBundle has been stripped of all information not needed for
            serving a query.
            */
            bool stripped_;

            /**
            The size of the labels in multiples of item length.
            */
            std::size_t label_size_;

            /**
            Maximum size of the bins.
            */
            std::size_t max_bin_size_;

            /**
            Holds the Paterson-Stockmeyer low-degree for this BinBundle.
            */
            std::size_t ps_low_degree_;

            /**
            The number of bins in the BinBundle.
            */
            std::size_t num_bins_;

            /**
            A cache of all the computations we can do on the bins. This is empty by default.
            */
            BinBundleCache cache_;

            /**
            Returns the modulus that defines the finite field that we're working in
            */
            const seal::Modulus &field_mod() const;

            /**
            Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is
            just the "matching" polynomial. For labeled PSI, this is the "matching" polynomial and
            the Newton interpolation polynomial. Resulting values are stored in cache_.
            */
            void regen_polyns();

            /**
            Batches this BinBundle's polynomials into SEAL Plaintexts. Resulting values are stored
            in cache_.
            */
            void regen_plaintexts();

        public:
            BinBundle(
                const CryptoContext &crypto_context,
                std::size_t label_size,
                std::size_t max_bin_size,
                std::size_t ps_low_degree,
                std::size_t num_bins,
                bool compressed,
                bool stripped);

            BinBundle(const BinBundle &copy) = delete;

            BinBundle(BinBundle &&source) = default;

            BinBundle &operator=(const BinBundle &assign) = delete;

            BinBundle &operator=(BinBundle &&assign) = default;

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is
            specified, no change is made to the BinBundle. On success, returns the size of the
            largest bin bins in the modified range, after insertion has taken place. On failed
            insertion, returns -1. On failure, no modification is made to the BinBundle.
            */
            template <typename T>
            std::int32_t multi_insert(
                const std::vector<T> &item_labels, std::size_t start_bin_idx, bool dry_run);

            /**
            Does a dry-run insertion of item-label pairs into sequential bins, beginning at
            start_bin_idx. This does not mutate the BinBundle. On success, returns the size of the
            largest bin bins in the modified range, after insertion has taken place. On failed
            insertion, returns -1.
            */
            template <typename T>
            std::int32_t multi_insert_dry_run(
                const std::vector<T> &item_labels, std::size_t start_bin_idx)
            {
                return multi_insert(item_labels, start_bin_idx, true);
            }

            /**
            Inserts item-label pairs into sequential bins, beginning at start_bin_idx. On success,
            returns the size of the largest bin bins in the modified range, after insertion has
            taken place. On failed insertion, returns -1. On failure, no modification is made to the
            BinBundle.
            */
            template <typename T>
            std::int32_t multi_insert_for_real(
                const std::vector<T> &item_labels, std::size_t start_bin_idx)
            {
                return multi_insert(item_labels, start_bin_idx, false);
            }

            /**
            Attempts to overwrite the stored items' labels with the given labels. Returns true iff
            it found a contiguous sequence of given items. If no such sequence was found, this
            BinBundle is not mutated. This function can be called on a
            BinBundle<std::vector<felt_t>> but it won't do anything except force the cache to get
            recomputed, so don't bother. The labeled case has T equal to std::pair<felt_t,
            std::vector<felt_t>>.
            */
            template <typename T>
            bool try_multi_overwrite(const std::vector<T> &item_labels, std::size_t start_bin_idx);

            /**
            Attempts to remove the stored items and labels. Returns true iff it found a contiguous
            sequence of given items and the data was successfully removed. If no such sequence was
            found, this BinBundle is not mutated.
            */
            bool try_multi_remove(const std::vector<felt_t> &items, std::size_t start_bin_idx);

            /**
            Sets the given labels to the set of labels associated with the sequence of items in this
            BinBundle, starting at start_idx. If any item is not present in its respective bin, this
            returns false and clears the given labels vector. Returns true on success.
            */
            bool try_get_multi_label(
                const std::vector<felt_t> &items,
                std::size_t start_bin_idx,
                std::vector<felt_t> &labels) const;

            /**
            Clears the contents of the BinBundle and wipes out the cache.
            */
            void clear(bool stripped = false);

            /**
            Wipes out the cache of the BinBundle
            */
            void clear_cache();

            /**
            Returns whether this BinBundle's cache needs to be recomputed
            */
            bool cache_invalid() const noexcept
            {
                return cache_invalid_;
            }

            /**
            Gets a constant reference to this BinBundle's cache. This will throw an exception if the
            cache is invalid. Check the cache before you wreck the cache.
            */
            const BinBundleCache &get_cache() const;

            /**
            Generates and caches all the polynomials and plaintexts that this BinBundle requires
            */
            void regen_cache();

            /**
            Returns a constant reference to the items in this BinBundle.
            */
            const std::vector<std::vector<felt_t>> &get_item_bins() const noexcept
            {
                return item_bins_;
            }

            /**
            Returns the size of the label in multiples of the item size.
            */
            std::size_t get_label_size() const noexcept
            {
                return label_size_;
            }

            /**
            Returns the number of bins.
            */
            std::size_t get_num_bins() const noexcept
            {
                return num_bins_;
            }

            /**
            Returns a constant reference to the label parts in this BinBundle.
            */
            const std::vector<std::vector<std::vector<felt_t>>> &get_label_bins() const noexcept
            {
                return label_bins_;
            }

            /**
            Returns whether this BinBundle is empty.
            */
            bool empty() const;

            /**
            Indicates whether the BinBundle has been stripped of all information not needed for
            serving a query.
            */
            bool is_stripped() const
            {
                return stripped_;
            }

            /**
            Strips the BinBundle of all information not needed for serving a query.
            */
            void strip();

            /**
            Saves the BinBundle to a stream.
            */
            std::size_t save(std::ostream &out, std::uint32_t bundle_idx) const;

            /**
            Loads the BinBundle from a buffer.
            */
            std::pair<std::uint32_t, std::size_t> load(gsl::span<const unsigned char> in);

            /**
            Loads the BinBundle from a stream.
            */
            std::pair<std::uint32_t, std::size_t> load(std::istream &in);
        }; // class BinBundle
    }      // namespace sender
} // namespace apsi
