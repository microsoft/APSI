// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <iostream>

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
    constexpr static std::uint32_t item_bit_count_min = 80;

    constexpr static std::uint32_t item_bit_count_max = 128;

    /**
    Contains a collection of parameters required to configure the protocol.
    */
    class PSIParams
    {
    public:
        using SEALParams = seal::EncryptionParameters;

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
            std::uint32_t table_size;
            std::uint32_t window_size;
            std::uint32_t max_items_per_bin;
            std::uint32_t hash_func_count;
        }; // struct TableParams

        const ItemParams &item_params() const
        {
            return item_params_;
        }

        const TableParams &table_params() const
        {
            return table_params_;
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

        PSIParams(const ItemParams &item_params, const TableParams &table_params, const SEALParams &seal_params) :
            item_params_(item_params), table_params_(table_params), seal_params_(seal_params)
        {
            initialize();
        }

    private:
        const ItemParams item_params_;

        const TableParams table_params_;

        const SEALParams seal_params_{ seal::scheme_type::BFV };

        std::uint32_t items_per_bundle_;

        std::uint32_t bundle_idx_count_;

        std::uint32_t item_bit_count_;

        std::uint32_t item_bit_count_per_felt_;

        void initialize();
    }; // class PSIParams

    void SaveParams(const PSIParams &params, std::vector<seal::SEAL_BYTE> &out);

    PSIParams LoadParams(const std::vector<seal::SEAL_BYTE> &in);
} // namespace apsi
