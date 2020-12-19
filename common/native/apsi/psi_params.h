// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <utility>
#include <iostream>
#include <string>

// APSI
#include "apsi/logging/log.h"
#include "apsi/util/utils.h"

// Kuku
#include "kuku/kuku.h"

// SEAL
#include "seal/encryptionparams.h"
#include "seal/util/common.h"

namespace apsi
{
    /**
    Contains a collection of parameters required to configure the protocol.
    */
    class PSIParams
    {
    public:
        class SEALParams : public seal::EncryptionParameters
        {
        public:
            SEALParams() : seal::EncryptionParameters(seal::scheme_type::bfv)
            {}
        };

        constexpr static std::uint32_t item_bit_count_min = 80;

        constexpr static std::uint32_t item_bit_count_max = 128;

        /**
        Parameters describing the item and label properties.
        */
        struct ItemParams
        {
            constexpr static std::uint32_t felts_per_item_max = 32;

            constexpr static std::uint32_t felts_per_item_min = 2;

            /**
            Specified how many SEAL batching slots are occupied by an item. This value must be a power of two.
            */
            std::uint32_t felts_per_item;
        };

        /**
        Table parameters.
        */
        struct TableParams
        {
            constexpr static std::uint32_t hash_func_count_min = 2;

            constexpr static std::uint32_t hash_func_count_max = 8;

            std::uint32_t table_size;

            std::uint32_t max_items_per_bin;

            std::uint32_t hash_func_count;
        }; // struct TableParams

        /**
        Query parameters.
        */
        struct QueryParams
        {
            std::uint32_t query_powers_count;
            
            /**
            Specifies a seed to be used for generating a PowersDag for these parameters. This can be left to be the
            default value (zero), or set to a different value that is known to result in a particular configuration for
            the PowersDag.
            */
            std::uint32_t powers_dag_seed = 0;
        };

        const ItemParams &item_params() const
        {
            return item_params_;
        }

        const TableParams &table_params() const
        {
            return table_params_;
        }

        const QueryParams &query_params() const
        {
            return query_params_;
        }

        const SEALParams &seal_params() const
        {
            return seal_params_;
        }

        std::uint32_t items_per_bundle() const
        {
            return items_per_bundle_;
        }

        std::uint32_t bins_per_bundle() const
        {
            return static_cast<std::uint32_t>(seal_params_.poly_modulus_degree());
        }

        std::uint32_t bundle_idx_count() const
        {
            return bundle_idx_count_;
        }

        std::int32_t item_bit_count() const
        {
            return item_bit_count_;
        }

        std::int32_t item_bit_count_per_felt() const
        {
            return item_bit_count_per_felt_;
        }

        PSIParams(
            const ItemParams &item_params,
            const TableParams &table_params,
            const QueryParams &query_params,
            const SEALParams &seal_params) :
            item_params_(item_params),
            table_params_(table_params),
            query_params_(query_params),
            seal_params_(seal_params)
        {
            initialize();
        }

        std::string to_string() const;

    private:
        const ItemParams item_params_;

        const TableParams table_params_;

        const QueryParams query_params_;

        const SEALParams seal_params_;

        std::uint32_t items_per_bundle_;

        std::uint32_t bundle_idx_count_;

        std::uint32_t item_bit_count_;

        std::uint32_t item_bit_count_per_felt_;

        void initialize();
    }; // class PSIParams

    /**
    Writes the PSIParams to a stream.
    */
    std::size_t SaveParams(const PSIParams &params, std::ostream &out);

    /**
    Reads the PSIParams from a stream.
    */
    std::pair<PSIParams, std::size_t> LoadParams(std::istream &in);
} // namespace apsi
