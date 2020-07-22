// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cmath>
#include <map>
#include <numeric>
#include <seal/biguint.h>
#include <seal/encryptionparams.h>
#include <stdexcept>
#include <string>
#include "apsi/logging/log.h"
#include "apsi/util/utils.h"
#include "kuku/kuku.h"

namespace apsi
{
    /**
    Contains a collection of parameters required to configure PSI and dependnecies.
    */
    class PSIParams
    {
    public:
        /**
        PSI configuration parameters and getters.
        */
        struct PSIConfParams
        {
            std::size_t sender_size;
            std::size_t sender_bin_size;
            // the number of chunks to split each item into
            std::size_t num_chunks;
            bool use_labels;
        }; // struct PSIConfParams

        const PSIConfParams &psiconf_params() const
        {
            return psiconf_params_;
        }

        inline std::size_t sender_size() const
        {
            return psiconf_params_.sender_size;
        }

        inline std::size_t sender_bin_size() const
        {
            return psiconf_params_.sender_bin_size;
        }

        inline std::size_t num_chunks() const
        {
            return psiconf_params_.num_chunks;
        }

        inline bool use_labels() const
        {
            return psiconf_params_.use_labels;
        }

        /**
        Table setup parameters and getters.
        */
        struct TableParams
        {
            std::uint32_t log_table_size;
            std::uint32_t window_size;
            std::size_t split_count;
            std::size_t split_size;
            std::uint32_t binning_sec_level;
            bool use_dynamic_split_count;
        }; // struct TableParams

        const TableParams &table_params() const
        {
            return table_params_;
        }

        inline std::uint32_t log_table_size() const
        {
            return table_params_.log_table_size;
        }

        inline std::uint32_t window_size() const
        {
            return table_params_.window_size;
        }

        inline std::size_t split_count() const
        {
            return table_params_.split_count;
        }

        inline std::size_t split_size() const
        {
            return table_params_.split_size;
        }

        inline std::uint32_t binning_sec_level() const
        {
            return table_params_.binning_sec_level;
        }

        inline bool use_dynamic_split_count() const
        {
            return table_params_.use_dynamic_split_count;
        }

        /**
        Cuckoo hashing parameters for Kuku and getters.
        */
        struct CuckooParams
        {
            // A larger hash_func_count leads to worse performance.
            // Kuku upperbounds hash_func_count, e.g. if item_bit_count = 120 then hash_func_count < 64.
            // Typically, 3 is enough.
            std::uint32_t hash_func_count;
            std::uint32_t hash_func_seed;
            std::uint32_t max_probe;
        }; // struct CuckooParams

        const CuckooParams &cuckoo_params() const
        {
            return cuckoo_params_;
        }

        inline std::uint32_t hash_func_count() const
        {
            return cuckoo_params_.hash_func_count;
        }

        inline std::uint32_t hash_func_seed() const
        {
            return cuckoo_params_.hash_func_seed;
        }

        inline std::uint32_t max_probe() const
        {
            return cuckoo_params_.max_probe;
        }

        /**
        Microsoft SEAL parameters and getters.
        */
        struct SEALParams
        {
            seal::EncryptionParameters encryption_params{ seal::scheme_type::BFV };
            std::uint32_t max_supported_degree;
        }; // struct SEALParams

        const SEALParams &seal_params() const
        {
            return seal_params_;
        }

        inline const seal::EncryptionParameters &encryption_params() const
        {
            return seal_params_.encryption_params;
        }

        inline std::uint32_t max_supported_degree() const
        {
            return seal_params_.max_supported_degree;
        }

        /**
        Extension field parameters and getters.
        */
        struct FFieldParams
        {
            std::uint64_t characteristic;
            std::uint32_t degree;
        }; // struct FFieldParams

        const FFieldParams &ffield_params() const
        {
            return ffield_params_;
        }

        inline std::uint64_t ffield_characteristic() const
        {
            return ffield_params_.characteristic;
        }

        inline std::uint32_t ffield_degree() const
        {
            return ffield_params_.degree;
        }

        /**
        Manual setters.
        */
        void set_sender_bin_size(std::size_t size)
        {
            logging::Log::debug("Manually setting sender bin size to be %i", size);
            psiconf_params_.sender_bin_size = size;
        }

        void set_split_count(std::size_t count)
        {
            logging::Log::debug("Manually setting split count to be %i", count);
            table_params_.split_count = count;
        }

        /**
        Other getters.
        */
        inline std::size_t table_size() const
        {
            return 1 << table_params_.log_table_size;
        }

        inline std::size_t batch_size() const
        {
            return encryption_params().poly_modulus_degree() / ffield_degree();
        }

        inline std::size_t batch_count() const
        {
            std::size_t batch = batch_size();
            return (table_size() + batch - 1) / batch;
        }

        PSIParams(
            const PSIConfParams &psi_params, const TableParams &table_params, const CuckooParams &cuckoo_params,
            const SEALParams &seal_params, const FFieldParams &ffield_params)
            : psiconf_params_(psi_params), table_params_(table_params), cuckoo_params_(cuckoo_params),
              seal_params_(seal_params), ffield_params_(ffield_params)
        {
            if (psiconf_params_.sender_bin_size == 0)
            {
                // if bin size is unset.
                logging::Log::debug("Updating sender bin size");
                update_sender_bin_size();
            }
            else
            {
                logging::Log::debug("Taking sender bin size = %i from command line", psiconf_params_.sender_bin_size);
            }

            validate();
        }

    private:
        PSIConfParams psiconf_params_;
        TableParams table_params_;
        CuckooParams cuckoo_params_;
        SEALParams seal_params_;
        FFieldParams ffield_params_;

        void update_sender_bin_size()
        {
            logging::Log::debug(
                "running balls in bins analysis with 2^%i bins and %i balls, with stat sec level = %i",
                table_params_.log_table_size, psiconf_params_.sender_size * cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level);
            psiconf_params_.sender_bin_size = util::compute_sender_bin_size(
                table_params_.log_table_size, psiconf_params_.sender_size, cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level, table_params_.split_count);
            logging::Log::debug("updated sender bin size to %i.", psiconf_params_.sender_bin_size);
        }

        /**
        Validate parameters
        */
        void validate() const
        {
            if (sender_bin_size() % split_count() != 0)
            {
                throw std::invalid_argument("Sender bin size must be a multiple of number of splits.");
            }
        }
    }; // class PSIParams
} // namespace apsi
