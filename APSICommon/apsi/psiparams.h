// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <map>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <cstdint>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/logging/log.h"
#include "apsi/tools/utils.h"

// SEAL
#include <seal/encryptionparams.h>
#include <seal/biguint.h>

// Cuckoo
#include "cuckoo/cuckoo.h"

using namespace apsi::logging;

namespace apsi
{
    class PSIParams
    {
    public:
        struct PSIConfParams
        {
            // Should not exceed 128. Moreover, should reserve several bits because of the requirement of current Cuckoo hashing impl.
            unsigned item_bit_count;
            bool use_oprf;
            bool use_labels;
            apsi::u64 sender_size;
            unsigned item_bit_length_used_after_oprf; // how many bits we take after oprf.

            // number of chunks to split each item into 
            unsigned num_chunks;

            unsigned sender_bin_size; 
        };

        struct CuckooParams
        {
            // Should not be too big, both due to the performance consideration and the requirement of current Cuckoo hashing impl.
            // For example, if item_bit_count = 120, then hash_func_count should be smaller than 2^6 = 64. But typically, 3 is enough.
            unsigned hash_func_count;
            unsigned hash_func_seed;
            unsigned max_probe;
        };

        struct TableParams
        {
            unsigned log_table_size;
            unsigned window_size;
            unsigned split_count;
            unsigned binning_sec_level;
        };

        struct SEALParams
        {
            seal::EncryptionParameters encryption_params{ seal::scheme_type::BFV };
            unsigned decomposition_bit_count;
        };

        struct ExFieldParams
        {
            u64 characteristic;
            unsigned degree;
        };

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
            if (sender_bin_size_ == 0) { // if bin size is unset.
                Log::info("updating sender bin size..."); 
                update_sender_bin_size();
            }
            else {
                Log::info("taking sender bin size = %i from command line...", sender_bin_size_); 
            }
            validate();
        }

        /********************************************
        Parameters from input: PSIConfParameters
        *********************************************/
        inline unsigned int item_bit_count() const
        {
            return psiconf_params_.item_bit_count;
        }

        inline unsigned int item_bit_length_used_after_oprf() const
        {
            return psiconf_params_.item_bit_length_used_after_oprf;
        }

        inline bool use_oprf() const
        {
            return psiconf_params_.use_oprf;
        }

        inline bool use_labels() const
        {
            return psiconf_params_.use_labels;
        }

        inline apsi::u64 sender_size() const
        {
            return psiconf_params_.sender_size;
        }

        inline unsigned int num_chunks() const
        {
            return psiconf_params_.num_chunks;
        }


        /********************************************
        Parameters from input: TableParameters
        *********************************************/
        inline unsigned int log_table_size() const
        {
            return table_params_.log_table_size;
        }

        inline unsigned int window_size() const
        {
            return table_params_.window_size;
        }

        inline unsigned int split_count() const
        {
            return table_params_.split_count;
        }

        inline unsigned int binning_sec_level() const
        {
            return table_params_.binning_sec_level;
        }

        /********************************************
        Parameters from input: CuckooParams
        *********************************************/
        inline unsigned int hash_func_count() const
        {
            return cuckoo_params_.hash_func_count;
        }

        inline unsigned int hash_func_seed() const
        {
            return cuckoo_params_.hash_func_seed;
        }

        inline unsigned int max_probe() const
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

        inline unsigned int decomposition_bit_count() const
        {
            return seal_params_.decomposition_bit_count;
        }

        /********************************************
        Parameters from input: ExFieldParams
        *********************************************/
        inline u64 exfield_characteristic() const
        {
            return exfield_params_.characteristic;
        }

        inline unsigned int exfield_degree() const
        {
            return exfield_params_.degree;
        }

        /********************************************
        Calculated parameters
        *********************************************/
        inline unsigned int sender_bin_size() const
        {
            return sender_bin_size_;
        }

        inline unsigned int table_size() const
        {
            return 1 << table_params_.log_table_size;
        }

        inline int split_size() const
        {
            return sender_bin_size() / split_count();
        }

        inline int batch_size() const
        {
            return static_cast<int>(encryption_params().poly_modulus_degree() / exfield_degree());
        }

        inline int batch_count() const
        {
            int batch = batch_size();
            return (table_size() + batch - 1) / batch;
        }

        inline int get_label_bit_count() const
        {
            if (!psiconf_params_.use_labels)
                return 0;

            return psiconf_params_.item_bit_count;
        }

        inline int get_label_byte_count() const
        {
            if (!psiconf_params_.use_labels)
                return 0;

            return (psiconf_params_.item_bit_count + 7) / 8;
        }

        // assuming one query.
        double log_fp_rate() {
            int bitcount = item_bit_count(); 
            if (psiconf_params_.use_oprf) { bitcount = item_bit_length_used_after_oprf(); } // currently hardcoded.
            return ((double)exfield_degree())* (log2(split_size())) + log2(split_count())- bitcount;
        }

		void set_sender_bin_size(unsigned size) {
			Log::info("manually setting sender bin size to be %i", size);
			sender_bin_size_ = size;
		}


		void set_split_count(unsigned count) {
			Log::info("manually setting split count to be %i", count);
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

        int sender_bin_size_;

        void update_sender_bin_size()
        {
            Log::info("running balls in bins analysis with 2^%i bins and %i balls, with stat sec level = %i", table_params_.log_table_size,
                psiconf_params_.sender_size *
                cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level
                );
            sender_bin_size_ = static_cast<int>(apsi::tools::compute_sender_bin_size(
                table_params_.log_table_size,
                psiconf_params_.sender_size,
                cuckoo_params_.hash_func_count,
                table_params_.binning_sec_level,
                table_params_.split_count));
            Log::info("final sender bin size = %i.", sender_bin_size_); 
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
                throw std::invalid_argument("Invalid for cuckoo: null bit and location index overflow to new uint64_t.");
            }

            if (item_bit_count() > max_item_bit_count)
            {
                throw std::invalid_argument("Item bit count cannot exceed max.");
            }


            int bitcount = item_bit_count(); 
            if (use_oprf()) {
                bitcount = item_bit_length_used_after_oprf();
            }
            int supported_bitcount = ((uint64_t)exfield_degree())* (seal_params_.encryption_params.plain_modulus().bit_count() - 1); 
            if (bitcount > supported_bitcount){
                apsi::logging::Log::warning("item bit count (%i) is too large to fit in slots (%i bits). ", bitcount, supported_bitcount);
            }

            if (item_bit_count() > (max_item_bit_count - 8))
            {
                // Not an error, but a warning.
                apsi::logging::Log::warning("Item bit count is close to its upper limit. Several bits should be reserved for appropriate Cuckoo hashing.");
            }
        }
    };
}
