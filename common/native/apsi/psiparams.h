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
            std::size_t item_bit_count;                  // <=max_item_bit_count=128, reserve extra bits for Kuku
            std::size_t item_bit_length_used_after_oprf; // the number of bits we take after oprf
            std::size_t num_chunks;                      // the number of chunks to split each item into
            bool use_labels;
            bool use_fast_membership; // faster configuration assuming query is always one item
        };                            // struct PSIConfParams

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

        inline std::size_t item_bit_count() const
        {
            return psiconf_params_.item_bit_count;
        }

        inline std::size_t item_bit_length_used_after_oprf() const
        {
            return psiconf_params_.item_bit_length_used_after_oprf;
        }

        inline std::size_t num_chunks() const
        {
            return psiconf_params_.num_chunks;
        }

        inline bool use_labels() const
        {
            return psiconf_params_.use_labels;
        }

        inline bool use_fast_membership() const
        {
            return psiconf_params_.use_fast_membership;
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
            bool dynamic_split_count; // TODO: Do not use bool for "*count".
        };                            // struct TableParams

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

        inline bool dynamic_split_count() const
        {
            return table_params_.dynamic_split_count;
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

        inline std::size_t label_bit_count() const
        {
            return psiconf_params_.use_labels ? psiconf_params_.item_bit_count : 0;
        }

        inline std::size_t label_byte_count() const
        {
            return psiconf_params_.use_labels ? (psiconf_params_.item_bit_count + 7) / 8 : 0;
        }

        // assuming one query.
        inline double log_fp_rate() const
        {
            return static_cast<double>(ffield_degree()) * log2(split_size()) + log2(split_count()) -
                   item_bit_length_used_after_oprf();
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

        // Constants
        constexpr static int max_item_bit_count = 128;

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
            if ((item_bit_count() + 63) / 64 !=
                (item_bit_count() + static_cast<std::uint32_t>(floor(log2(hash_func_count()))) + 1 + 1 + 63) / 64)
            {
                throw std::invalid_argument("Invalid for cuckoo: null bit and location index overflow to new std::uint64_t.");
            }
            if (item_bit_count() > max_item_bit_count)
            {
                throw std::invalid_argument("Item bit count cannot exceed max.");
            }
            if (item_bit_count() > (max_item_bit_count - 8))
            {
                // Not an error, but a warning.
                logging::Log::warning("Item bit count is close to its upper limit. Several bits should be reserved for "
                                      "appropriate Cuckoo hashing.");
            }
            std::uint64_t supported_bitcount =
                static_cast<std::uint64_t>(ffield_degree()) * static_cast<std::uint64_t>(seal_params_.encryption_params.plain_modulus().bit_count() - 1);
            if (item_bit_length_used_after_oprf() > supported_bitcount)
            {
                logging::Log::warning(
                    "item bit count (%i) is too large to fit in slots (%i bits). ", item_bit_length_used_after_oprf(),
                    supported_bitcount);
            }
        }
    }; // class PSIParams
} // namespace apsi
