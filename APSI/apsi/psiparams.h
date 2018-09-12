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
#include "seal/encryptionparams.h"
#include "seal/biguint.h"
#include "seal/bigpoly.h"
#include "seal/smallmodulus.h"

// Cuckoo
#include "cuckoo/cuckoo.h"

namespace apsi
{
    struct CuckooParams
    {
        unsigned hash_func_count;
        unsigned hash_func_seed;
        unsigned max_probe;
    };

    struct TableParams
    {
        unsigned log_table_size;
        //unsigned sender_bin_size;
        unsigned window_size;
        unsigned split_count;
        unsigned binning_sec_level;
    };

    struct SEALParams
    {
        struct ExFieldParams
        {
            u64 exfield_characteristic;
            unsigned exfield_degree;
        } exfield_params;

        seal::EncryptionParameters encryption_params{ seal::scheme_type::BFV };
        unsigned decomposition_bit_count;
    };

    class PSIParams
    {
    public:
        PSIParams(
            unsigned item_bit_count,
            bool use_oprf,
            u64 sender_set_size,
            TableParams table_params,
            CuckooParams cuckoo_params,
            SEALParams seal_params)
                : log_table_size_(table_params.log_table_size), 
                  table_size_(1 << log_table_size_),
                  window_size_(table_params.window_size),
                  //sender_bin_size_(table_params.sender_bin_size),
                  sender_set_size_(sender_set_size),
                  binning_sec_level_(table_params.binning_sec_level),
                  split_count_(table_params.split_count),
                  use_oprf_(use_oprf),
                  encryption_params_(seal_params.encryption_params),
                  decomposition_bit_count_(seal_params.decomposition_bit_count),
                  hash_func_count_(cuckoo_params.hash_func_count), 
                  hash_func_seed_(cuckoo_params.hash_func_seed), 
                  max_probe_(cuckoo_params.max_probe),
                  item_bit_count_(item_bit_count), 
                  exfield_characteristic_(seal_params.exfield_params.exfield_characteristic), 
                  exfield_degree_(seal_params.exfield_params.exfield_degree)
        {
            compute_sender_bin_size();
        }

        void validate() const
        {
            if (sender_bin_size_ % split_count_ != 0)
            {
                throw std::invalid_argument("Sender bin size must be a multiple of number of splits.");
            }

            if ((item_bit_count_ + 63) / 64 != (item_bit_count_ + static_cast<int>(floor(log2(hash_func_count_))) + 1 + 1 + 63) / 64)
            {
                throw std::invalid_argument("Invalid for cuckoo: null bit and location index overflow to new uint64_t.");
            }

            if (item_bit_count_ > max_item_bit_count)
            {
                throw std::invalid_argument("Item bit count cannot exceed max.");
            }

            if (item_bit_count_ > (max_item_bit_count - 8))
            {
                // Not an error, but a warning.
                apsi::logging::Log::warning("Item bit count is close to its upper limit. Several bits should be reserved for appropriate Cuckoo hashing.");
            }
        }

        inline bool use_oprf() const
        {
            return use_oprf_;
        }

        inline int log_table_size() const
        {
            return log_table_size_;
        }

        inline int table_size() const
        {
            return table_size_;
        }

        inline int hash_func_count() const
        {
            return hash_func_count_;
        }

        inline int hash_func_seed() const
        {
            return hash_func_seed_;
        }

        inline int max_probe() const
        {
            return max_probe_;
        }

        inline int item_bit_count() const
        {
            return item_bit_count_;
        }

        inline u64 exfield_characteristic() const
        {
            return exfield_characteristic_;
        }

        inline unsigned exfield_degree() const
        {
            return exfield_degree_;
        }

        inline int split_count() const
        {
            return split_count_;
        }

        inline int split_size() const
        {
            return sender_bin_size_ / split_count_;
        }

        inline int batch_size() const
        {
            return encryption_params_.poly_modulus_degree() / exfield_degree_;
        }

        inline int batch_count() const
        {
            int batch = batch_size();
            return (table_size_ + batch - 1) / batch;
        }

        inline int decomposition_bit_count() const
        {
            return decomposition_bit_count_;
        }

        inline int sender_bin_size() const
        {
            return sender_bin_size_;
        }

        inline u64 sender_set_size() const
        {
            return sender_set_size_;
        }

        inline void set_sender_set_size(u64 size)
        {
            sender_set_size_ = size;
            compute_sender_bin_size();
        }

        inline int window_size() const
        {
            return window_size_;
        }

        inline const seal::EncryptionParameters &encryption_params() const
        {
            return encryption_params_;
        }

        inline int get_label_bit_count() const { return value_bit_length_; }

        inline int get_label_byte_count() const { return value_byte_length_; }

        void set_value_bit_count(int bits)
        {
            value_bit_length_ = bits;
            value_byte_length_ = (bits + 7) / 8;
        }

        bool use_low_degree_poly() const { return use_low_degree_poly_; }

        void set_use_low_degree_poly(bool b) { use_low_degree_poly_ = b; }

        bool debug() const { return debug_; }

        void enable_debug() { debug_ = true; }

        void disable_debug() { debug_ = false; }

        // Constants
        constexpr static int max_item_bit_count = 128;

    private:
        int log_table_size_;

        int table_size_;

        int window_size_;

        int sender_bin_size_;

        u64 sender_set_size_;

        int binning_sec_level_;

        int split_count_;

        bool use_oprf_;

        int value_bit_length_ = 0;
        
        int value_byte_length_ = 0;

        bool use_low_degree_poly_ = false;
        
        bool debug_ = false;

        seal::EncryptionParameters encryption_params_;

        int decomposition_bit_count_;

        /* Should not be too big, both due to the performance consideration and the requirement of current Cuckoo hashing impl.
        For example, if item_bit_count = 120, then hash_func_count should be smaller than 2^6 = 64. But typically, 3 is enough. */
        int hash_func_count_;

        int hash_func_seed_;

        int max_probe_;

        /* Should not exceed 128. Moreover, should reserve several bits because of the requirement of current Cuckoo hashing impl. */
        int item_bit_count_;

        u64 exfield_characteristic_;

        unsigned exfield_degree_;


        inline void compute_sender_bin_size()
        {
            sender_bin_size_ = static_cast<int>(apsi::tools::round_up_to(
                apsi::tools::get_bin_size(
                    1ull << log_table_size_,
                    sender_set_size_ * hash_func_count_,
                    binning_sec_level_),
                static_cast<u64>(split_count_)));

            validate();
        }
    };
}
