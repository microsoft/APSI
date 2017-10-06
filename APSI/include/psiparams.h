#pragma once

#include <string>
#include <map>
#include "biguint.h"
#include "bigpoly.h"
#include "smallmodulus.h"

#include <cmath>

namespace apsi
{
    
    class PSIParams
    {
    public:

        PSIParams(
            int sender_total_thread_count = 1,
            int sender_session_thread_count = 1,
            int receiver_thread_count = 1,
            int log_table_size = 12,
            int sender_bin_size = 128,
            int window_size = 4,
            int number_of_splits = 128,
            int decomposition_bit_count = 58,
            int hash_func_count = 3,  
            int hash_func_seed = 0,
            int max_probe = 1000,
            int item_bit_length = 120,  
            /* The following parameters should be consistent with each other. */
            uint64_t exfield_characteristic = 0x1E01,
            seal::BigPoly exfield_polymod = seal::BigPoly("1x^16 + 3E"),
            int log_poly_degree = 12,
            int coeff_mod_bit_count = 116,
            
            uint32_t port = 4000,
            std::string endpoint = "APSI")
            :
            sender_total_thread_count_(sender_total_thread_count),
            sender_session_thread_count_(sender_session_thread_count),
            receiver_thread_count_(receiver_thread_count),
            log_table_size_(log_table_size), table_size_(1 << log_table_size),
            sender_bin_size_(sender_bin_size), window_size_(window_size), number_of_splits_(number_of_splits), 
            decomposition_bit_count_(decomposition_bit_count),
            hash_func_count_(hash_func_count), hash_func_seed_(hash_func_seed), max_probe_(max_probe),
            item_bit_length_(item_bit_length), reduced_item_bit_length_(item_bit_length - log_table_size + floor(log2(hash_func_count)) + 1 + 1),
            exfield_characteristic_(exfield_characteristic), exfield_polymod_(exfield_polymod),
            log_poly_degree_(log_poly_degree), poly_degree_(1 << log_poly_degree),
            coeff_mod_bit_count_(coeff_mod_bit_count),
            apsi_port_(port), apsi_endpoint_(endpoint)
        {
            
        }

        void validate();

        inline int log_table_size() const
        {
            return log_table_size_;
        }

        void set_log_table_size(int log_table_size)
        {
            log_table_size_ = log_table_size;
            table_size_ = 1 << log_table_size_;
            reduced_item_bit_length_ = item_bit_length_ - log_table_size_ + floor(log2(hash_func_count_)) + 1 + 1;
        }

        inline int table_size() const
        {
            return table_size_;
        }

        inline int hash_func_count() const
        {
            return hash_func_count_;
        }

        void set_hash_func_count(int hash_func_count)
        {
            hash_func_count_ = hash_func_count;
            reduced_item_bit_length_ = item_bit_length_ - log_table_size_ + floor(log2(hash_func_count_)) + 1 + 1;
        }

        inline int hash_func_seed() const
        {
            return hash_func_seed_;
        }

        void set_hash_func_seed(int seed)
        {
            hash_func_seed_ = seed;
        }

        inline int max_probe() const
        {
            return max_probe_;
        }

        void set_max_probe(int max_probe)
        {
            max_probe_ = max_probe;
        }

        inline int item_bit_length() const
        {
            return item_bit_length_;
        }

        inline void set_item_bit_length(int item_bit_length)
        {
            item_bit_length_ = item_bit_length;
            reduced_item_bit_length_ = item_bit_length_ - log_table_size_ + floor(log2(hash_func_count_)) + 1 + 1;
        }

        inline int reduced_item_bit_length()
        {
            return reduced_item_bit_length_;
        }

        inline uint64_t exfield_characteristic() const
        {
            return exfield_characteristic_;
        }

        inline void set_exfield_characteristic(uint64_t characteristic)
        {
            exfield_characteristic_ = characteristic;
        }

        inline const seal::BigPoly& exfield_polymod() const
        {
            return exfield_polymod_;
        }

        inline void set_exfield_polymod(const seal::BigPoly& poly)
        {
            exfield_polymod_ = poly;
        }

        inline int number_of_splits() const
        {
            return number_of_splits_;
        }

        void set_number_of_splits(int number_of_splits)
        {
            number_of_splits_ = number_of_splits;
        }

        inline int split_size() const
        {
            return sender_bin_size_ / number_of_splits_;
        }

        inline int batch_size() const
        {
            return poly_degree_ / (exfield_polymod_.significant_coeff_count() - 1);
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

        inline void set_decomposition_bit_count(int dbc)
        {
            decomposition_bit_count_ = dbc;
        }

        inline int sender_bin_size() const
        {
            return sender_bin_size_;
        }

        void set_sender_bin_size(int sender_bin_size)
        {
            sender_bin_size_ = sender_bin_size;
        }

        inline int window_size() const
        {
            return window_size_;
        }

        void set_window_size(int window_size)
        {
            window_size_ = window_size;
        }
        
        inline int poly_degree() const
        {
            return poly_degree_;
        }

        inline int log_poly_degree() const
        {
            return log_poly_degree_;
        }

        inline void set_log_poly_degree(int log_degree)
        {
            log_poly_degree_ = log_degree;
            poly_degree_ = 1 << log_poly_degree_;
        }

        inline int sender_total_thread_count() const
        {
            return sender_total_thread_count_;
        }

        void set_sender_total_thread_count(int sender_total_thread_count)
        {
            sender_total_thread_count_ = sender_total_thread_count;
        }

        inline int sender_session_thread_count() const
        {
            return sender_session_thread_count_;
        }

        void set_sender_session_thread_count(int sender_session_thread_count)
        {
            sender_session_thread_count_ = sender_session_thread_count;
        }

        inline int receiver_thread_count() const
        {
            return receiver_thread_count_;
        }

        void set_receiver_thread_count(int receiver_thread_count)
        {
            receiver_thread_count_ = receiver_thread_count;
        }

        inline void set_coeff_mod_bit_count(int coeff_mod_bit_count)
        {
            coeff_mod_bit_count_ = coeff_mod_bit_count;
        }

        std::vector<seal::SmallModulus> coeff_modulus();

        inline uint32_t apsi_port() const
        {
            return apsi_port_;
        }

        void set_apsi_port(uint32_t port)
        {
            apsi_port_ = port;
        }

        inline std::string apsi_endpoint() const
        {
            return apsi_endpoint_;
        }

        void set_apsi_endpoint(std::string endpoint)
        {
            apsi_endpoint_ = endpoint;
        }



    private:

        int log_table_size_;

        int table_size_;

        int log_poly_degree_;

        int poly_degree_;

        int coeff_mod_bit_count_;

        int window_size_;

        int sender_bin_size_;

        int number_of_splits_;

        int decomposition_bit_count_;

        /* Should not be too big, both due to the performance consideration and the requirement of current Cuckoo hashing impl.
        For example, if item_bit_length = 120, then hash_func_count should be smaller than 2^6 = 64. But typically, 3 is enough. */
        int hash_func_count_;

        int hash_func_seed_;

        int max_probe_;

        /* Should not exceed 128. Moreover, should reserve several bits because of the requirement of current Cuckoo hashing impl. */
        int item_bit_length_;

        int reduced_item_bit_length_;

        int sender_total_thread_count_;

        int sender_session_thread_count_;

        int receiver_thread_count_;

        std::uint64_t exfield_characteristic_;

        seal::BigPoly exfield_polymod_;

        static std::map<std::string, int> upperbound_on_B;

        uint32_t apsi_port_;

        std::string apsi_endpoint_;
    };


}