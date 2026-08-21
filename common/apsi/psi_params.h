// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
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
            Specified how many SEAL batching slots are occupied by an item.
            */
            std::uint32_t felts_per_item = 0;
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
        Returns an approximate base-2 logarithm of the false-positive probability per receiver's
        item.
        */
        [[nodiscard]]
        double log2_fpp() const
        {
            return std::min<double>(
                0.0,
                (-static_cast<double>(item_bit_count_per_felt_) +
                 std::log2(static_cast<double>(table_params_.max_items_per_bin))) *
                    item_params_.felts_per_item);
        }

        /**
        Writes the PSIParams to a stream.
        */
        std::size_t save(std::ostream &out) const;

        /**
        Reads the PSIParams from a stream.
        */
        [[nodiscard]]
        static std::pair<PSIParams, std::size_t> Load(std::istream &in);

        /**
        Reads the PSIParams from a JSON string
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

        void initialize();
    }; // class PSIParams
} // namespace apsi
