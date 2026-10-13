// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <utility>

// SEAL
#include "seal/encryptionparams.h"

namespace apsi {
    /**
    Contains a collection of parameters required to configure the protocol.
    */
    class PSIParams {
    public:
        /**
        Specifies the Microsoft SEAL encryption parameters for the BFV homomorphic encryption
        scheme.
        */
        class SEALParams : public seal::EncryptionParameters {
        public:
            SEALParams() : seal::EncryptionParameters(seal::scheme_type::bfv)
            {}
        };

        constexpr static std::uint32_t item_bit_count_min = 80;

        constexpr static std::uint32_t item_bit_count_max = 128;

        /**
        The smallest item_bit_count allowed for parameters that use match tags; see uses_tags. The
        tag then decides a match, and the bits of an item only select its point in a bin, so this
        only keeps bin bundles from filling with almost nothing for want of points. It never binds
        in practice, as the plain modulus gives at least 13 bits per field element.
        */
        constexpr static std::uint32_t item_bit_count_min_with_tags = 8;

        /**
        The smallest tag_bit_count allowed for parameters that use match tags. A receiver's item
        that is not in the sender's set passes the tag check against one bin bundle with
        probability 2^-tag_bit_count, so this keeps log2_fpp_per_bin_bundle at -40 or below. That
        is a bound per receiver's item and bin bundle, not per query: see
        sender::SenderDB::log2_fpp.
        */
        constexpr static std::uint32_t tag_bit_count_min = 40;

        /**
        The version a serialized PSIParams carries when it uses match tags. Parameters without match
        tags are written with apsi_serialization_version, exactly as by APSI 1.x. APSI 1.x checks
        the version against apsi_serialization_version, and so refuses parameters with match tags,
        and every SenderDB holding them, rather than misreading them as parameters without.
        */
        constexpr static std::uint32_t tag_serialization_version = 2;

        /**
        An upper bound on the size, in bytes, this charges to the encrypted query a receiver builds
        from these parameters. The query consists of bundle_idx_count() * query_powers.size()
        ciphertexts, each charged as 2 * poly_modulus_degree * |coeff_modulus| 64-bit words, so
        this single bound constrains table_size, query_powers, and felts_per_item together. It
        does not meaningfully constrain |coeff_modulus|, which is bounded separately by
        coeff_modulus_size_max: that factor enters here multiplied by the ciphertext count, which
        a caller wanting a long modulus chain would simply drive down to one.

        The charge deliberately overstates what is transmitted. A fresh ciphertext sits at the
        first data level, whose modulus omits the special prime, and the query is sent
        seed-compressed by symmetric encryption; both make the wire form smaller than the charge.
        Overstating is the safe direction for a bound.

        A bound on the number of ciphertexts would not be equivalent. Lengthening the modulus chain
        enlarges every ciphertext at an unchanged count, so a count bound would leave the total free
        to grow with |coeff_modulus| alone; only the total size is a meaningful measure. Raising
        poly_modulus_degree, by contrast, enlarges every ciphertext while proportionally reducing
        bundle_idx_count(), leaving the total unchanged, so it is not an inflation this bound need
        reject. The most demanding parameter set in parameters/ is charged 30 MiB, leaving this
        bound roughly a factor of 17 of headroom.
        */
        constexpr static std::uint64_t query_byte_count_max = static_cast<std::uint64_t>(512) << 20;

        /**
        An upper bound on the number of primes in the coefficient modulus.

        Cost here is quadratic in the number of primes and is paid whatever the rest of the
        parameters say, because a modulus chain of this length is materialized by every
        SEALContext built from these parameters, and again by the relinearization keys the
        receiver generates from it. Measured at poly_modulus_degree 32768: five primes cost 63 MiB,
        sixteen cost 463 MiB, thirty-two cost 1695 MiB. Security validation at tc128 caps the chain
        by total bit width rather than by count, and so admits over thirty narrow primes; it is not
        a useful bound on this.

        The largest coefficient modulus in parameters/ has five primes. Chain length tracks the
        multiplicative depth of the circuit, which is bounded in turn by max_items_per_bin, so this
        leaves room for any depth the other bounds admit.
        */
        constexpr static std::uint32_t coeff_modulus_size_max = 12;

        /**
        Parameters describing the item and label properties.
        */
        struct ItemParams {
            constexpr static std::uint32_t felts_per_item_max = 32;

            constexpr static std::uint32_t felts_per_item_min = 2;

            /**
            The smallest felts_per_item allowed for parameters that use match tags. An item's field
            elements then only select it within its bin, so a single one suffices.
            */
            constexpr static std::uint32_t felts_per_item_min_with_tags = 1;

            /**
            An upper bound on tag_part_count. Each tag part costs a polynomial per bin, a
            polynomial evaluation per bin bundle in every query, and a ciphertext per bin bundle
            in every response, so a parameter set needing more than a handful is better served by
            more bits per item. This leaves ample room above any useful value.
            */
            constexpr static std::uint32_t tag_part_count_max = 64;

            /**
            Specified how many SEAL batching slots are occupied by an item.
            */
            std::uint32_t felts_per_item = 0;

            /**
            The number of match tag parts, each of which is as large as an item. Zero, the
            default, selects matching polynomials, as in APSI 1.x: a receiver's item matches when
            every one of its field elements is a root of a bin's matching polynomial. A non-zero
            value selects match tags instead: the sender stores with every item a pseudorandom tag
            of tag_part_count * item_bit_count bits, derived from the item's OPRF output as
            util::compute_match_tag describes, and a receiver's item matches only when the sender
            returns exactly the receiver's own tag for it. A non-member then passes with probability
            2^-tag_bit_count per bin bundle, however many items a bin holds, so felts_per_item can
            be as small as one. See PSIParams::uses_tags.
            */
            std::uint32_t tag_part_count = 0;
        };

        /**
        Table parameters.
        */
        struct TableParams {
            constexpr static std::uint32_t hash_func_count_min = 1;

            constexpr static std::uint32_t hash_func_count_max = 8;

            /**
            An upper bound on table_size. The receiver's cuckoo table and the vectors indexed by it
            grow with table_size independently of the encryption parameters, so this bound is needed
            in addition to PSIParams::query_byte_count_max. The largest table_size in parameters/ is
            16384, so this leaves a factor of 64 of headroom.
            */
            constexpr static std::uint32_t table_size_max = static_cast<std::uint32_t>(1) << 20;

            /**
            An upper bound on max_items_per_bin.

            This is the degree of the matching polynomial. The receiver turns it into a set of
            target powers -- max_items_per_bin of them when ps_low_degree is zero, and far fewer
            under Paterson-Stockmeyer -- which PowersDag::configure then searches pairwise. The
            search is quadratic in that set, so with ps_low_degree zero the cost is dominated by
            this one value: measured, 8100 target powers configure in 0.46 s, 32768 in 9.1 s, and
            65536 in 43 s. Nothing else in the parameter set restrains it.

            The largest max_items_per_bin in parameters/ is 8100, so this leaves a factor of four
            of headroom. A parameter set at this bound still costs several seconds of the
            receiver's own CPU before a query is sent; the bound makes that finite, not free.
            */
            constexpr static std::uint32_t max_items_per_bin_max = static_cast<std::uint32_t>(1)
                                                                   << 15;

            /**
            Specified the size of the cuckoo hash table for storing the receiver's items.
            */
            std::uint32_t table_size = 0;

            /**
            Specifies the number of sender's items stored in a single hash table bin. A larger value
            requires a deeper encrypted computation, or more powers of the encrypted query to be
            sent from the receiver to the sender, but reduces the number of ciphertexts sent from
            the sender to the receiver.
            */
            std::uint32_t max_items_per_bin = 0;

            /**
            The number of hash functions used in receiver's cuckoo hashing.
            */
            std::uint32_t hash_func_count = 0;
        }; // struct TableParams

        /**
        Query parameters.
        */
        struct QueryParams {
            /**
            If set to a non-zero value, signals that the Paterson-Stockmeyer algorithm should be
            used for evaluating the matching and label polynomials. First all powers of the query,
            from 1 up to ps_low_degree, will be computed from the base specified in query_powers.
            Next, the matching and label polynomials will be evaluated using the Paterson-Stockmeyer
            algorithm. This number cannot exceed max_items_per_bin.
            */
            std::uint32_t ps_low_degree = 0;

            /**
            The encrypted powers of the query that are sent from the receiver to the sender. The set
            must contain at least the value 1, cannot contain 0, and cannot contain values larger
            than max_items_per_bin. Any value in query_powers larger than ps_low_degree must be a
            multiple of ps_low_degree + 1. Specific sets of powers will result in a lower depth
            computation requiring smaller encryption parameters, and may subsequently reduce both
            the computation and communication cost.
            */
            std::set<std::uint32_t> query_powers;
        };

        [[nodiscard]]
        const ItemParams &item_params() const
        {
            return item_params_;
        }

        [[nodiscard]]
        const TableParams &table_params() const
        {
            return table_params_;
        }

        [[nodiscard]]
        const QueryParams &query_params() const
        {
            return query_params_;
        }

        [[nodiscard]]
        const SEALParams &seal_params() const
        {
            return seal_params_;
        }

        [[nodiscard]]
        std::uint32_t items_per_bundle() const
        {
            return items_per_bundle_;
        }

        [[nodiscard]]
        std::uint32_t bins_per_bundle() const
        {
            return bins_per_bundle_;
        }

        [[nodiscard]]
        std::uint32_t bundle_idx_count() const
        {
            return bundle_idx_count_;
        }

        [[nodiscard]]
        std::uint32_t item_bit_count() const
        {
            return item_bit_count_;
        }

        [[nodiscard]]
        std::uint32_t item_bit_count_per_felt() const
        {
            return item_bit_count_per_felt_;
        }

        /**
        Returns the number of match tag parts; zero for parameters that do not use match tags.
        See ItemParams::tag_part_count.
        */
        [[nodiscard]]
        std::uint32_t tag_part_count() const
        {
            return item_params_.tag_part_count;
        }

        /**
        Returns the number of bits in a match tag, tag_part_count() * item_bit_count(); zero for
        parameters that do not use match tags.
        */
        [[nodiscard]]
        std::uint32_t tag_bit_count() const
        {
            return tag_bit_count_;
        }

        /**
        Returns whether these parameters use match tags, that is, whether tag_part_count() is
        non-zero.

        With match tags, the sender stores with every item, as the first tag_part_count() parts
        of its label, a tag derived from the item's OPRF output (util::compute_match_tag), and
        computes no matching polynomial. A query is answered with the label results alone, and
        the receiver accepts an item exactly when the sender returns the item's own tag. The
        receiver therefore needs the label keys of its items, which the OPRF provides, whether or
        not the sender's items have labels. Without match tags, everything is as in APSI 1.x.
        */
        [[nodiscard]]
        bool uses_tags() const
        {
            return item_params_.tag_part_count != 0;
        }

        PSIParams(
            ItemParams item_params,
            TableParams table_params,
            QueryParams query_params,
            SEALParams seal_params)
            : item_params_(item_params), table_params_(table_params),
              query_params_(std::move(query_params)), seal_params_(std::move(seal_params))
        {
            initialize();
        }

        PSIParams(const PSIParams &copy) = default;

        PSIParams &operator=(const PSIParams &copy) = default;

        [[nodiscard]]
        std::string to_string() const;

        /**
        Returns an upper bound on the base-2 logarithm of the false-positive probability per
        receiver's item, against a SINGLE bin bundle.

        Without match tags, an item that is not in the sender's set is reported when each of its
        field elements is a root of its bin's matching polynomial, even if the roots come from
        different items of the sender, which bounds the probability by
        (max_items_per_bin / 2^item_bit_count_per_felt) to the power felts_per_item. With match
        tags, it is reported only when the sender returns exactly its tag, which happens with
        probability 2^-tag_bit_count however many items the bin holds. A tag is derived from a
        128-bit label key, though, and two items with the same key have the same tag however long
        it is, so this returns -min(tag_bit_count(), 128).

        This is not the probability a deployment sees, and is not meant to be read as one. A
        receiver's item is matched against every bin bundle at its bundle index, and a location
        holding more items than max_items_per_bin spills into further bundles, each answered
        separately; a match from any of them is reported. A query of many items is likelier to
        contain a false positive than a query of one. Both terms are missing here, and together
        they are worth several bits and more than ten for some parameter sets.

        PSIParams cannot supply either: it does not know how large a sender's set is, nor how
        many items a query will carry. sender::SenderDB::log2_fpp knows the first and takes the
        second, and is what a deployment should consult.
        */
        [[nodiscard]]
        double log2_fpp_per_bin_bundle() const
        {
            if (uses_tags()) {
                return -static_cast<double>(std::min<std::uint32_t>(tag_bit_count_, 128));
            }

            return std::min<double>(
                0.0,
                (-static_cast<double>(item_bit_count_per_felt_) +
                 std::log2(static_cast<double>(table_params_.max_items_per_bin))) *
                    item_params_.felts_per_item);
        }

        /**
        Writes the PSIParams to a stream.

        Parameters without match tags are written exactly as APSI 1.x writes them, with
        apsi_serialization_version as their version. Parameters with match tags are written with
        tag_serialization_version and the tag part count; see tag_serialization_version for why.
        */
        std::size_t save(std::ostream &out) const;

        /**
        Reads the PSIParams from a stream.

        Accepts parameters without match tags written with apsi_serialization_version, and
        parameters with match tags written with tag_serialization_version. Anything else,
        including a version that disagrees with whether a tag part count is present, is refused
        with std::runtime_error.
        */
        [[nodiscard]]
        static std::pair<PSIParams, std::size_t> Load(std::istream &in);

        /**
        Reads the PSIParams from a JSON string.

        The key item_params.tag_part_count selects match tags; absent or zero, the parameters do
        not use them. The top-level key version names the version of the serialized parameters the
        file describes. Parameters with match tags must name tag_serialization_version.
        Parameters without them may name apsi_serialization_version or leave the key out, as
        the parameter files of APSI 1.x do. Anything else is refused with std::runtime_error.

        The version is required with match tags because APSI 1.x and older ignore
        item_params.tag_part_count, as they ignore every key they do not know, and so could read a
        file meant for match tags as parameters without them. Versions since APSI 1.0.0 refuse a
        version they do not implement, and so refuse such a file instead.
        */
        [[nodiscard]]
        static PSIParams Load(const std::string &in);

    private:
        ItemParams item_params_;

        TableParams table_params_;

        QueryParams query_params_;

        SEALParams seal_params_;

        std::uint32_t items_per_bundle_ = 0;

        std::uint32_t bins_per_bundle_ = 0;

        std::uint32_t bundle_idx_count_ = 0;

        std::uint32_t item_bit_count_ = 0;

        std::uint32_t item_bit_count_per_felt_ = 0;

        std::uint32_t tag_bit_count_ = 0;

        void initialize();
    }; // class PSIParams
} // namespace apsi
