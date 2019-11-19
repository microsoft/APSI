// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>
#include <map>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <seal/encryptionparams.h>
#include <seal/biguint.h>
#include "kuku/kuku.h"
#include "apsi/logging/log.h"
#include "apsi/tools/utils.h"

namespace apsi
{
    class PSIParams
    {
    public:
        struct PSIConfParams
        {
            // Should not exceed 128. Moreover, should reserve several bits because of the requirement of current Cuckoo hashing impl.
            u32 item_bit_count;
            bool use_labels;
            bool use_fast_membership; // faster configuration assuming query is always one item.
            u64 sender_size;
            u32 item_bit_length_used_after_oprf; // how many bits we take after oprf.

            // number of chunks to split each item into 
            u32 num_chunks;
            u64 sender_bin_size;
        }; // struct PSIConfParams

        struct CuckooParams
        {
            // Should not be too big, both due to the performance consideration and the requirement of current Cuckoo hashing impl.
            // For example, if item_bit_count = 120, then hash_func_count should be smaller than 2^6 = 64. But typically, 3 is enough.
            u32 hash_func_count;
            u32 hash_func_seed;
            u32 max_probe;
        }; // struct CuckooParams

        struct TableParams
        {
            u32 log_table_size;
            u32 window_size;
            u32 split_count;
            u32 split_size;
            u32 binning_sec_level;
            bool      dynamic_split_count;
        }; // struct TableParams

        struct SEALParams
        {
            seal::EncryptionParameters encryption_params{ seal::scheme_type::BFV };
            u32 max_supported_degree;
        }; // struct SEALParams

        struct ExFieldParams
        {
            u64 characteristic;
            u32 degree;
        }; // struct ExFieldParams

    public:
        PSIParams(
            const PSIConfParams& psi_params,
            const TableParams& table_params,
            const CuckooParams& cuckoo_params,
            const SEALParams& seal_params,
            const ExFieldParams& exfield_params)
            : psiconf_params_(psi_params),
              table_params_(table_params),
              cuckoo_params_(cuckoo_params),
              seal_params_(seal_params),
              exfield_params_(exfield_params)
        {
            sender_bin_size_ = psiconf_params_.sender_bin_size;
            if (sender_bin_size_ == 0)
            {
                // if bin size is unset.
                logging::Log::debug("Updating sender bin size");
                update_sender_bin_size();
            }
            else
            {
                logging::Log::debug("Taking sender bin size = %i from command line", sender_bin_size_);
            }

            validate();
        }

        /********************************************
        Parameters from input: PSIConfParameters
        *********************************************/
        inline u32 item_bit_count() const
        {
            return psiconf_params_.item_bit_count;
        }

        inline u32 item_bit_length_used_after_oprf() const
        {
            return psiconf_params_.item_bit_length_used_after_oprf;
        }

        inline bool use_labels() const
        {
            return psiconf_params_.use_labels;
        }

        inline bool use_fast_membership() const
        {
            return psiconf_params_.use_fast_membership;
        }

        inline u64 sender_size() const
        {
            return psiconf_params_.sender_size;
        }

        inline u32 num_chunks() const
        {
            return psiconf_params_.num_chunks;
        }


        /********************************************
        Parameters from input: TableParameters
        *********************************************/
        inline u32 log_table_size() const
        {
            return table_params_.log_table_size;
        }

        inline u32 window_size() const
        {
            return table_params_.window_size;
        }

        inline u32 split_count() const
        {
            return table_params_.split_count;
        }

        inline u32 split_size() const
        {
            return table_params_.split_size;
        }

        inline u32 binning_sec_level() const
        {
            return table_params_.binning_sec_level;
        }

        inline bool dynamic_split_count() const
        {
            return table_params_.dynamic_split_count;
        }

        /********************************************
        Parameters from input: CuckooParams
        *********************************************/
        inline u32 hash_func_count() const
        {
            return cuckoo_params_.hash_func_count;
        }

        inline u32 hash_func_seed() const
        {
            return cuckoo_params_.hash_func_seed;
        }

        inline u32 max_probe() const
        {
            return cuckoo_params_.max_probe;
        }

        /********************************************
        Parameters from input: SEALParams
        *********************************************/
        inline const seal::EncryptionParameters& encryption_params() const
        {
            return seal_params_.encryption_params;
        }

        inline u32 max_supported_degree() const
        {
            return seal_params_.max_supported_degree;
        }

        /********************************************
        Parameters from input: ExFieldParams
        *********************************************/
        inline u64 exfield_characteristic() const
        {
            return exfield_params_.characteristic;
        }

        inline u32 exfield_degree() const
        {
            return exfield_params_.degree;
        }

        /********************************************
        Calculated parameters
        *********************************************/
        inline u64 sender_bin_size() const
        {
            return sender_bin_size_;
        }

        inline u32 table_size() const
        {
            return 1 << table_params_.log_table_size;
        }

        inline u32 batch_size() const
        {
            return static_cast<u32>(encryption_params().poly_modulus_degree() / exfield_degree());
        }

        inline u32 batch_count() const
        {
            u32 batch = batch_size();
            return (table_size() + batch - 1) / batch;
        }

        inline u32 get_label_bit_count() const
        {
            if (!psiconf_params_.use_labels)
                return 0;

            return psiconf_params_.item_bit_count;
        }

        inline u32 get_label_byte_count() const
        {
            if (!psiconf_params_.use_labels)
                return 0;

            return (psiconf_params_.item_bit_count + 7) / 8;
        }

        // assuming one query.
        double log_fp_rate() {
            int bitcount = item_bit_length_used_after_oprf(); // currently hardcoded.

            return static_cast<double>(exfield_degree()) * log2(split_size()) + log2(split_count()) - bitcount;
        }

        void set_sender_bin_size(u64 size) {
            logging::Log::debug("Manually setting sender bin size to be %i", size);
            sender_bin_size_ = size;
        }


        void set_split_count(u32 count) {
            logging::Log::debug("Manually setting split count to be %i", count);
            table_params_.split_count = count;
        }

        // Allow access to param structures
        const PSIConfParams& get_psiconf_params() const { return psiconf_params_; }
        const TableParams& get_table_params() const     { return table_params_; }
        const CuckooParams& get_cuckoo_params() const   { return cuckoo_params_; }
        const SEALParams& get_seal_params() const       { return seal_params_; }
        const ExFieldParams& get_exfield_params() const { return exfield_params_; }

        // Constants
        constexpr static int max_item_bit_count = 128;


    private:
        PSIConfParams psiconf_params_;
        TableParams   table_params_;
        CuckooParams  cuckoo_params_;
        SEALParams    seal_params_;
        ExFieldParams exfield_params_;

        u64 sender_bin_size_;

        void update_sender_bin_size()
        {
            logging::Log::debug("running balls in bins analysis with 2^%i bins and %i balls, with stat sec level = %i", table_params_.log_table_size,
                psiconf_params_.sender_size *
                cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level
                );
            sender_bin_size_ = tools::compute_sender_bin_size(
                table_params_.log_table_size,
                psiconf_params_.sender_size,
                cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level,
                table_params_.split_count);
            logging::Log::debug("updated sender bin size to %i.", sender_bin_size_); 
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

            if ((item_bit_count() + 63) / 64 != (item_bit_count() + static_cast<int>(floor(log2(hash_func_count()))) + 1 + 1 + 63) / 64)
            {
                throw std::invalid_argument("Invalid for cuckoo: null bit and location index overflow to new u64.");
            }

            if (item_bit_count() > max_item_bit_count)
            {
                throw std::invalid_argument("Item bit count cannot exceed max.");
            }

            u32 bitcount = item_bit_length_used_after_oprf();

            u64 supported_bitcount = ((u64)exfield_degree()) * (seal_params_.encryption_params.plain_modulus().bit_count() - 1);
            if (bitcount > supported_bitcount)
            {
                logging::Log::warning("item bit count (%i) is too large to fit in slots (%i bits). ", bitcount, supported_bitcount);
            }

            if (item_bit_count() > (max_item_bit_count - 8))
            {
                // Not an error, but a warning.
                logging::Log::warning("Item bit count is close to its upper limit. Several bits should be reserved for appropriate Cuckoo hashing.");
            }
        }
    }; // class PSIParams
} // namespace apsi
