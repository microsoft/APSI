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
    /**
    Contains a collection of parameters required to configure the protocol.
    */
    class PSIParams
    {
    public:
        using SEALParams = seal::EncryptionParameters;

        constexpr static int item_bit_count = 120;

        constexpr static int label_bit_count = item_bit_count;

        /**
        Table setup parameters and getters.
        */
        struct TableParams
        {
            std::uint32_t table_size;
            std::uint32_t window_size;
            std::uint32_t split_size;
            std::uint32_t hash_func_count;
        }; // struct TableParams

        const TableParams &table_params() const
        {
            return table_params_;
        }

        const SEALParams &seal_params() const
        {
            return seal_params_;
        }

        std::uint32_t bins_per_item() const
        {
            return bins_per_item_;
        }

        std::uint32_t bundle_size() const
        {
            return bundle_size_;
        }

        inline std::uint32_t bundle_idx_count() const
        {
            return bundle_idx_count_;
        }

        PSIParams(const TableParams &table_params, const SEALParams &seal_params) :
            table_params_(table_params), seal_params_(seal_params)
        {
            // Perform a minimal parameter check here to ensure internal constants can be initialized
            if (seal_params_.plain_modulus().bit_count() < 2)
            {
                throw std::invalid_argument("plain_modulus is not large enough");
            }
            if (!seal_params_.poly_modulus_degree())
            {
                throw std::invalid_argument("poly_modulus_degree is not large enough");
            }

            initialize();
        }

    private:
        TableParams table_params_;

        SEALParams seal_params_{ seal::scheme_type::BFV };

        std::uint32_t bins_per_item_;

        std::uint32_t bundle_size_;

        std::uint32_t bundle_idx_count_;

        bool initialized_ = false;

        void initialize()
        {
            // How many bits can be use for each item chunk?
            int bit_count_per_chunk = seal_params_.plain_modulus().bit_count() - 1;

            // How many chunks do we need to hold the entire item?
            auto temp = static_cast<std::uint32_t>((item_bit_count + bit_count_per_chunk - 1) / bit_count_per_chunk);

            // We still need to round up to the nearest power of two to avoid splitting items across bin bundles
            int bit_count = seal::util::get_significant_bit_count(temp);
            bool is_power_of_two = temp & (temp - 1);
            bins_per_item_ = is_power_of_two ? temp : std::uint32_t(1) << bit_count;

            // Next compute the bundle size
            bundle_size_ = static_cast<std::uint32_t>(seal_params_.poly_modulus_degree() / bins_per_item_);

            // Finally compute the number of bundle indices
            bundle_idx_count_ = (table_params_.table_size + bundle_size_ - 1) / bundle_size_;

            initialized_ = true;
        }
    }; // class PSIParams

    void SaveParams(const PSIParams &params, std::vector<seal::SEAL_BYTE> &out);

    PSIParams LoadParams(const std::vector<seal::SEAL_BYTE> &in);
} // namespace apsi
