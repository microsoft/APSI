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

namespace apsi::sender {
    /**
    Represents a polynomial with coefficients that are field elements. Coefficients are stored
    in degree-increasing order, so, for example, the constant term is at index 0.
    */
    using FEltPolyn = std::vector<apsi::util::felt_t>;

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
        Evaluates the polynomial on the given ciphertext. We don't compute the powers of the input
        ciphertext C ourselves. Instead we assume they've been precomputed and accept the powers:
        (C, C², C³, ...) as input. The number of powers provided MUST be at least
        batched_coeffs.size()-1. Throws std::invalid_argument if the polynomial has no coefficients.
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

        Throws std::invalid_argument if the polynomial has no coefficients.
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
            return !batched_coeffs.empty();
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
        roots are precisely the items in the bin. Note that this field is empty when the
        BinBundle uses match tags, which need no matching polynomial.
        */
        std::vector<FEltPolyn> felt_matching_polyns;

        /**
        For each bin, stores the Newton interpolation polynomial whose value at each item in the bin
        equals the item's corresponding label. Note that this field is empty when doing unlabeled
        PSI without match tags. With match tags, the first label parts are the parts of the items'
        match tags, so this field is not empty even for unlabeled PSI.
        */
        std::vector<std::vector<FEltPolyn>> felt_interp_polyns;

        /**
        Cached seal::Plaintext representation of the "matching" polynomial of this BinBundle.
        Note that this field is empty when the BinBundle uses match tags.
        */
        BatchedPlaintextPolyn batched_matching_polyn;

        /**
        Cached seal::Plaintext representation of the interpolation polynomial of this BinBundle.
        Note that this field is empty when doing unlabeled PSI without match tags.
        */
        std::vector<BatchedPlaintextPolyn> batched_interp_polyns;
    }; // struct BinBundleCache

    /**
    Represents a specific bin bundle and stores the associated data.

    A BinBundle with a non-zero tag part count uses match tags (see PSIParams::uses_tags). Its
    label parts then begin with that many parts of each item's match tag, followed by the parts
    of the item's encrypted label, if any, so its label size is never zero. Such a BinBundle
    computes no matching polynomial: a query is answered with the label polynomials alone. With
    few bits per item, two different items can share their field elements, so a BinBundle with
    match tags that is not stripped also keeps each item's HashedItem alongside its field
    elements, and every operation that looks for an existing item finds it by its HashedItem.
    The tag is used only by the receiver, to decide matches.

    The operations taking an apsi::util::TaggedAlgItemLabel or a HashedItem are the ones for a
    BinBundle with match tags, and the others are for a BinBundle without them. Each kind throws
    std::logic_error on the other kind of BinBundle.
    */
    class BinBundle {
    private:
        /**
        This is true iff cache_ needs to be regenerated
        */
        bool cache_invalid_{ true };

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
        std::vector<std::vector<apsi::util::felt_t>> item_bins_;

        /**
        For a BinBundle with match tags that is not stripped, the HashedItem of the item at each
        position of item_bins_, in the same positions; empty otherwise. The HashedItem identifies an
        item, as two items can share their field elements.
        */
        std::vector<std::vector<HashedItem>> hashed_item_bins_;

        /**
        Item-size chunks of the label (decomposed into field elements) for each bin in the
        BinBundle. The dimensions are, in order:
            - Components of the label
            - Bins in the BinBundle
            - Field elements in the bin
        */
        std::vector<std::vector<std::vector<apsi::util::felt_t>>> label_bins_;

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
        bool stripped_{};

        /**
        The size of the labels in multiples of item length.
        */
        std::size_t label_size_;

        /**
        The number of label parts, at the beginning of each label, that hold the item's match
        tag; zero when the BinBundle does not use match tags.
        */
        std::size_t tag_part_count_;

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
        [[nodiscard]] const seal::Modulus &field_mod() const;

        /**
        Computes and caches the appropriate polynomials of each bin. For unlabeled PSI, this is
        just the "matching" polynomial. For labeled PSI, this is the "matching" polynomial and
        the Newton interpolation polynomial. With match tags, this is only the Newton
        interpolation polynomials. Resulting values are stored in cache_.
        */
        void regen_polyns();

        /**
        Batches this BinBundle's polynomials into SEAL Plaintexts. Resulting values are stored
        in cache_.
        */
        void regen_plaintexts();

    public:
        /**
        Creates an empty BinBundle. A non-zero tag_part_count makes it use match tags: the first
        tag_part_count of its label_size label parts then hold the match tags of its items, so
        label_size must be at least tag_part_count. Throws std::invalid_argument if the
        arguments are inconsistent.
        */
        BinBundle(
            CryptoContext crypto_context,
            std::size_t label_size,
            std::size_t max_bin_size,
            std::size_t ps_low_degree,
            std::size_t num_bins,
            bool compressed,
            bool stripped,
            std::size_t tag_part_count = 0);

        BinBundle(const BinBundle &copy) = delete;

        BinBundle(BinBundle &&source) = default;

        BinBundle &operator=(const BinBundle &assign) = delete;

        BinBundle &operator=(BinBundle &&assign) = default;

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx. If dry_run is
        specified, no change is made to the BinBundle. On success, returns the size of the
        largest bin in the modified range, after insertion has taken place. On failed
        insertion, returns -1. On failure, no modification is made to the BinBundle. Throws
        std::logic_error if the BinBundle uses match tags.
        */
        template <typename T>
        std::int32_t multi_insert(
            const std::vector<T> &item_labels, std::size_t start_bin_idx, bool dry_run);

        /**
        Inserts an item and its label parts, tag parts first, into sequential bins of a BinBundle
        that uses match tags, beginning at start_bin_idx, and records the item's HashedItem with it.
        Like the labeled form of the template, this fails if one of the item's field elements is
        already in its bin, since the label polynomials need distinct points. If dry_run is
        specified, no change is made to the BinBundle. On success, returns the size of the largest
        bin in the modified range, after insertion has taken place. On failed insertion, returns -1,
        and no modification is made to the BinBundle. Memory is reserved before anything is changed,
        so if it cannot be, the exception leaves the BinBundle as it was, and nothing is thrown once
        the BinBundle has begun to change. Throws std::logic_error if the BinBundle does not use
        match tags.
        */
        std::int32_t multi_insert(
            const apsi::util::TaggedAlgItemLabel &item, std::size_t start_bin_idx, bool dry_run);

        /**
        Does a dry-run insertion of item-label pairs into sequential bins, beginning at
        start_bin_idx. This does not mutate the BinBundle. On success, returns the size of the
        largest bin in the modified range, after insertion has taken place. On failed
        insertion, returns -1.
        */
        template <typename T>
        std::int32_t multi_insert_dry_run(
            const std::vector<T> &item_labels, std::size_t start_bin_idx)
        {
            return multi_insert(item_labels, start_bin_idx, true);
        }

        /**
        Does a dry-run insertion of an item into a BinBundle that uses match tags; see
        multi_insert.
        */
        std::int32_t multi_insert_dry_run(
            const apsi::util::TaggedAlgItemLabel &item, std::size_t start_bin_idx)
        {
            return multi_insert(item, start_bin_idx, true);
        }

        /**
        Inserts item-label pairs into sequential bins, beginning at start_bin_idx. On success,
        returns the size of the largest bin in the modified range, after insertion has
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
        Inserts an item into a BinBundle that uses match tags; see multi_insert.
        */
        std::int32_t multi_insert_for_real(
            const apsi::util::TaggedAlgItemLabel &item, std::size_t start_bin_idx)
        {
            return multi_insert(item, start_bin_idx, false);
        }

        /**
        Attempts to overwrite the stored items' labels with the given labels. Returns true iff
        it found a contiguous sequence of given items. If no such sequence was found, this
        BinBundle is not mutated. This function can be called on an unlabeled BinBundle but it won't
        do anything except force the cache to get recomputed, so don't bother. The labeled case has
        T equal to std::pair<apsi::util::felt_t, std::vector<apsi::util::felt_t>>. Throws
        std::logic_error if the BinBundle uses match tags.
        */
        template <typename T>
        bool try_multi_overwrite(const std::vector<T> &item_labels, std::size_t start_bin_idx);

        /**
        Attempts to overwrite the label parts of an item stored in a BinBundle that uses match
        tags with the given ones. The item is found by its HashedItem alone. Returns true iff the
        item was found, in which case all its label parts are overwritten; otherwise this
        BinBundle is not mutated. Throws std::logic_error if the BinBundle does not use match
        tags.
        */
        bool try_multi_overwrite(
            const apsi::util::TaggedAlgItemLabel &item, std::size_t start_bin_idx);

        /**
        Returns whether the given items are stored in sequential bins, beginning at
        start_bin_idx, found exactly as try_multi_overwrite and try_multi_remove find them. Any
        labels given are ignored. Unlike those functions, this never changes the BinBundle, so it
        can be used to find out where an item is stored before deciding what to change. Throws
        std::logic_error if the BinBundle uses match tags.
        */
        template <typename T>
        bool multi_contains(const std::vector<T> &item_labels, std::size_t start_bin_idx) const;

        /**
        Returns whether the item with the given field elements and HashedItem is stored in
        sequential bins of a BinBundle that uses match tags, beginning at start_bin_idx. The item
        is found by its HashedItem alone, exactly as try_multi_overwrite, try_multi_remove and
        try_get_multi_label find it, and this never changes the BinBundle. Throws
        std::logic_error if the BinBundle does not use match tags.
        */
        bool multi_contains(
            const std::vector<apsi::util::felt_t> &items,
            const HashedItem &item,
            std::size_t start_bin_idx) const;

        /**
        Returns whether the given item is stored in a BinBundle that uses match tags; see the
        overload taking a HashedItem. Its label parts are ignored.
        */
        bool multi_contains(
            const apsi::util::TaggedAlgItemLabel &item, std::size_t start_bin_idx) const;

        /**
        Attempts to remove the stored items and labels. Returns true iff it found a contiguous
        sequence of given items and the data was successfully removed. If no such sequence was
        found, this BinBundle is not mutated. Throws std::logic_error if the BinBundle uses match
        tags.
        */
        bool try_multi_remove(
            const std::vector<apsi::util::felt_t> &items, std::size_t start_bin_idx);

        /**
        Attempts to remove the item with the given field elements and HashedItem, and its label
        parts, from sequential bins of a BinBundle that uses match tags, beginning at
        start_bin_idx. The item is found by its HashedItem alone. Returns true iff it found the
        item and removed it; otherwise this BinBundle is not mutated. Throws std::logic_error if
        the BinBundle does not use match tags.
        */
        bool try_multi_remove(
            const std::vector<apsi::util::felt_t> &items,
            const HashedItem &item,
            std::size_t start_bin_idx);

        /**
        Sets the given labels to the set of labels associated with the sequence of items in this
        BinBundle, starting at start_bin_idx. If any item is not present in its respective bin, this
        returns false and clears the given labels vector. Returns true on success. Throws
        std::logic_error if the BinBundle uses match tags.
        */
        bool try_get_multi_label(
            const std::vector<apsi::util::felt_t> &items,
            std::size_t start_bin_idx,
            std::vector<apsi::util::felt_t> &labels) const;

        /**
        Sets the given labels to the label parts of the item with the given field elements and
        HashedItem, stored in sequential bins of a BinBundle that uses match tags, beginning at
        start_bin_idx, laid out as the overload without a HashedItem lays them out: part p of the
        item's i-th field element is at labels[p * items.size() + i]. The tag parts come first. The
        item is found by its HashedItem alone. If it is not found, this returns false and clears the
        given labels vector. Returns true on success. Throws std::logic_error if the BinBundle does
        not use match tags.
        */
        bool try_get_multi_label(
            const std::vector<apsi::util::felt_t> &items,
            const HashedItem &item,
            std::size_t start_bin_idx,
            std::vector<apsi::util::felt_t> &labels) const;

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
        [[nodiscard]] bool cache_invalid() const noexcept
        {
            return cache_invalid_;
        }

        /**
        Gets a constant reference to this BinBundle's cache. This will throw an exception if the
        cache is invalid. Check the cache before you wreck the cache.
        */
        [[nodiscard]] const BinBundleCache &get_cache() const;

        /**
        Generates and caches all the polynomials and plaintexts that this BinBundle requires
        */
        void regen_cache();

        /**
        Returns a constant reference to the HashedItems kept alongside the items of a BinBundle
        that uses match tags and is not stripped, in the same positions as get_item_bins; empty
        otherwise.
        */
        [[nodiscard]] const std::vector<std::vector<HashedItem>> &get_hashed_item_bins()
            const noexcept
        {
            return hashed_item_bins_;
        }

        /**
        Returns a constant reference to the items in this BinBundle.
        */
        [[nodiscard]] const std::vector<std::vector<apsi::util::felt_t>> &get_item_bins()
            const noexcept
        {
            return item_bins_;
        }

        /**
        Returns the size of the label in multiples of the item size.
        */
        [[nodiscard]] std::size_t get_label_size() const noexcept
        {
            return label_size_;
        }

        /**
        Returns the number of label parts that hold the match tags of the items; zero when the
        BinBundle does not use match tags.
        */
        [[nodiscard]] std::size_t get_tag_part_count() const noexcept
        {
            return tag_part_count_;
        }

        /**
        Returns whether this BinBundle uses match tags.
        */
        [[nodiscard]] bool uses_tags() const noexcept
        {
            return tag_part_count_ != 0;
        }

        /**
        Returns the number of bins.
        */
        [[nodiscard]] std::size_t get_num_bins() const noexcept
        {
            return num_bins_;
        }

        /**
        Returns a constant reference to the label parts in this BinBundle.
        */
        [[nodiscard]] const std::vector<std::vector<std::vector<apsi::util::felt_t>>> &
        get_label_bins() const noexcept
        {
            return label_bins_;
        }

        /**
        Returns whether this BinBundle is empty.
        */
        [[nodiscard]] bool empty() const;

        /**
        Indicates whether the BinBundle has been stripped of all information not needed for
        serving a query.
        */
        [[nodiscard]] bool is_stripped() const
        {
            return stripped_;
        }

        /**
        Strips the BinBundle of all information not needed for serving a query.
        */
        void strip();

        /**
        Saves the BinBundle to a stream. A BinBundle with match tags writes no matching
        polynomials, and, unless it is stripped, writes the HashedItems of its items. A BinBundle
        without match tags writes exactly what it always has.
        */
        std::size_t save(std::ostream &out, std::uint32_t bundle_idx) const;

        /**
        Loads the BinBundle from a buffer. The data must have been saved by a BinBundle of the
        same kind: with match tags, it must hold no matching polynomials, and must hold the
        HashedItems of its items exactly when it is not stripped; without match tags, it must
        hold the matching polynomials and no HashedItems. Throws std::runtime_error if the data
        is invalid or of the other kind.
        */
        std::pair<std::uint32_t, std::size_t> load(gsl::span<const unsigned char> in);

        /**
        Loads the BinBundle from a stream; see the overload taking a buffer.
        */
        std::pair<std::uint32_t, std::size_t> load(std::istream &in);
    }; // class BinBundle
} // namespace apsi::sender
