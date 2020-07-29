// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <stdexcept>
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
    constexpr static std::int32_t item_bit_count_min = 80;

    constexpr static std::int32_t item_bit_count_max = 128;

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
            constexpr static std::uint32_t num_chunks_max = 32;

            constexpr static std::uint32_t num_chunks_min = 2;

            /**
            Specified how many SEAL batching slots are occupied by an item. This value must be a power of two.
            */
            std::uint32_t num_chunks;
        };

        /**
        Table parameters.
        */
        struct TableParams
        {
            std::uint32_t table_size;
            std::uint32_t window_size;
            std::uint32_t split_size;
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

        std::int32_t item_bit_count_per_chunk() const
        {
            return item_bit_count_per_chunk_;
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

        std::int32_t item_bit_count_;

        std::int32_t item_bit_count_per_chunk_;

        void initialize()
        {
            // Checking the validity of parameters 
            if (item_params_.num_chunks < ItemParams::num_chunks_min ||
                item_params_.num_chunks > ItemParams::num_chunks_max)
            {
                throw std::invalid_argument("num_chunks is too large or too small");
            }
            if (!item_params_.num_chunks || (item_params_.num_chunks & (item_params_.num_chunks - 1)))
            {
                throw std::invalid_argument("num_chunks is not a power of two");
            }
            if (!seal_params_.plain_modulus().is_prime() || seal_params_.plain_modulus().value() == 2)
            {
                throw std::invalid_argument("plain_modulus is not an odd prime");
            }
            if (!seal_params_.poly_modulus_degree() ||
                (seal_params_.poly_modulus_degree() & (seal_params_.poly_modulus_degree() - 1)))
            {
                throw std::invalid_argument("poly_modulus_degree is not a power of two");
            }

            // Compute the bit-length of an item
            item_bit_count_per_chunk_ = seal_params_.plain_modulus().bit_count() - 1;
            item_bit_count_ = item_bit_count_per_chunk_ * static_cast<std::int32_t>(item_params_.num_chunks);

            // Compute how many items fit into a bundle
            items_per_bundle_ = static_cast<std::uint32_t>(
                seal_params_.poly_modulus_degree() / item_params_.num_chunks);

            // Finally compute the number of bundle indices
            bundle_idx_count_ = (table_params_.table_size + items_per_bundle_ - 1) / items_per_bundle_;
        }
    }; // class PSIParams

    void SaveParams(const PSIParams &params, std::vector<seal::SEAL_BYTE> &out);

    PSIParams LoadParams(const std::vector<seal::SEAL_BYTE> &in);
} // namespace apsi
