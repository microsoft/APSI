#pragma once

// STD
#include <string>
#include <map>
#include <cmath>
#include <numeric>
#include <stdexcept>

// APSI
#include "apsi/tools/binsizemath.h"

// SEAL
#include "seal/encryptionparams.h"
#include "seal/biguint.h"
#include "seal/bigpoly.h"
#include "seal/smallmodulus.h"

// Cuckoo
#include "cuckoo/cuckoo.h"

namespace apsi
{
    //enum class InterpolateMode
    //{
    //    None,
    //    ShortStrings,
    //    LongStrings
    //};

    enum class OprfType
    {
        None,
        PK
    };

    struct CuckooParams
    {
        cuckoo::CuckooMode cuckoo_mode;
        unsigned hash_func_count;
        unsigned hash_func_seed;
        unsigned max_probe;
    };

    struct TableParams
    {
        unsigned log_table_size;
        unsigned sender_bin_size;
        unsigned window_size;
        unsigned split_count;
    };

    struct SEALParams
    {
        struct ExFieldParams
        {
            std::uint64_t exfield_characteristic;
            seal::BigPoly exfield_polymod;
        } exfield_params;
        seal::EncryptionParameters encryption_params;
        unsigned decomposition_bit_count;
    };

    class PSIParams
    {
    public:
        PSIParams(
            unsigned item_bit_length,
            TableParams table_params,
            CuckooParams cuckoo_params,
            SEALParams seal_params,
            OprfType oprfType,
            std::uint32_t port = 4000,
            std::string endpoint = "APSI") :
            log_table_size_(table_params.log_table_size), 
            table_size_(1 << log_table_size_),
            sender_bin_size_(table_params.sender_bin_size), 
            window_size_(table_params.window_size),
            split_count_(table_params.split_count),
            oprf_type_(oprfType),
            decomposition_bit_count_(seal_params.decomposition_bit_count),
            cuckoo_mode_(cuckoo_params.cuckoo_mode),
            hash_func_count_(cuckoo_params.hash_func_count), 
            hash_func_seed_(cuckoo_params.hash_func_seed), 
            max_probe_(cuckoo_params.max_probe),
            item_bit_length_(item_bit_length), 
            exfield_characteristic_(seal_params.exfield_params.exfield_characteristic), 
            exfield_polymod_(seal_params.exfield_params.exfield_polymod),
            encryption_params_(seal_params.encryption_params),
            //log_poly_degree_(seal_params.log_poly_degree), 
            //poly_degree_(seal_params.encryption_params.poly_modulus().coeff_count() - 1),
            //coeff_mod_bit_count_(seal_params.coeff_mod_bit_count),
            apsi_port_(port), 
            apsi_endpoint_(endpoint)
        {
        }

        void validate();

        inline bool use_pk_oprf() const
        {
            return oprf_type_ == OprfType::PK;
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

        inline int item_bit_length() const
        {
            return item_bit_length_;
        }

        inline std::uint64_t exfield_characteristic() const
        {
            return exfield_characteristic_;
        }

        inline const seal::BigPoly &exfield_polymod() const
        {
            return exfield_polymod_;
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
            return (encryption_params_.poly_modulus().coeff_count() - 1) / (exfield_polymod_.significant_coeff_count() - 1);
        }

        inline int number_of_batches() const
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

        inline int window_size() const
        {
            return window_size_;
        }

        //inline int poly_degree() const
        //{
        //    return poly_degree_;
        //}

        //inline int log_poly_degree() const
        //{
        //    return log_poly_degree_;
        //}

        //std::vector<seal::SmallModulus> coeff_modulus();

        inline const seal::EncryptionParameters &encryption_params() const
        {
            return encryption_params_;
        }

        inline std::uint32_t apsi_port() const
        {
            return apsi_port_;
        }

        inline std::string apsi_endpoint() const
        {
            return apsi_endpoint_;
        }

        inline const cuckoo::CuckooMode get_cuckoo_mode() const
        { 
            return cuckoo_mode_; 
        }

        inline int get_value_bit_length() const
        {
            return value_bit_length_;
        }

        inline int get_value_byte_length() const
        {
            return value_byte_length_;
        }


        void set_value_bit_length(int bits)
        {
            value_bit_length_ = bits;
            value_byte_length_ = (bits + 7) / 8;
        }

    private:
        int log_table_size_;

        int table_size_;

        //int log_poly_degree_;

        //int poly_degree_;

        //int coeff_mod_bit_count_;

        int window_size_;

        int sender_bin_size_;

        int split_count_;

        OprfType oprf_type_;

        cuckoo::CuckooMode cuckoo_mode_;

        int value_bit_length_, value_byte_length_;

        seal::EncryptionParameters encryption_params_;

        int decomposition_bit_count_;

        /* Should not be too big, both due to the performance consideration and the requirement of current Cuckoo hashing impl.
        For example, if item_bit_length = 120, then hash_func_count should be smaller than 2^6 = 64. But typically, 3 is enough. */
        int hash_func_count_;

        int hash_func_seed_;

        int max_probe_;

        /* Should not exceed 128. Moreover, should reserve several bits because of the requirement of current Cuckoo hashing impl. */
        int item_bit_length_;

        std::uint64_t exfield_characteristic_;

        seal::BigPoly exfield_polymod_;

        std::uint32_t apsi_port_;

        std::string apsi_endpoint_;
    };
}