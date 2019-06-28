// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

#include <vector>
#include <random>
#include <memory>
#include "cuckoo/common.h"
#include "cuckoo/locfunc.h"

namespace cuckoo
{
    class QueryResult
    {
        friend class CuckooInterface;

    public:
        QueryResult() = default;
        
        inline i64 table_index() const
        {
#ifdef CUCKOO_DEBUG
            if (!*this) 
            {
                throw std::runtime_error("item not in table");
            }
#endif
            return table_index_;
        }

        inline i64 loc_func_index() const
        {
#ifdef CUCKOO_DEBUG
            if (!*this) 
            {
                throw std::runtime_error("item not in table");
            }
#endif
            return loc_func_index_;
        }

        inline operator bool() const
        {
            return loc_func_index_ != -1;
        }

    private:
        QueryResult(u64 table_index, u64 loc_func_index) 
        {
#ifdef SEAL_DEBUG
            if(table_index >= max_table_size)	
            {
                throw std::invalid_argument("table_index too large");
            }
            if(loc_func_index >= max_loc_func_count)	
            {
                throw std::invalid_argument("loc_func_index too large");
            }
#endif
            table_index_ = static_cast<i64>(table_index);
            loc_func_index_ = static_cast<i64>(loc_func_index);
        }

        i64 table_index_ = -1;

        i64 loc_func_index_  = -1;
    };

    class CuckooInterface
    {
    public:
        // Adds a single item to the cuckoo table.
        virtual bool insert(item_type item) = 0;

        // returns true of the provided item is contained in the hash table.
        virtual QueryResult query_item(item_type item);

        // Returns the encoded version of the inserted items.
        virtual const std::vector<item_type> &get_encodings() = 0;

        // returns the locations that this item may live at.
        virtual u64 get_location(item_type item, u64 hash_idx) = 0;

        virtual void clear_hash_table() = 0;

        virtual u64 loc_func_count() const = 0;

        virtual u64 encoding_bit_length() const = 0;

        //virtual bool has_item_at(int table_index) const = 0;

        /*
        Basic getters
        */
        inline const std::vector<item_type>& input_table() const 
        { 
            return input_table_; 
        }

        inline std::vector<item_type> &input_table() 
        { 
            return input_table_; 
        }

        inline u64 loc_func_seed() const 
        { 
            return loc_func_seed_; 
        }

        inline u64 log_table_size() const 
        { 
            return log_table_size_; 
        }

        inline u64 table_size() const 
        { 
            return 1ULL << log_table_size(); 
        }

        inline u64 max_probe() const 
        { 
            return max_probe_; 
        }

        inline const item_type &null_value() const 
        { 
            return null_value_; 
        }

        inline bool is_null(u64 index)
        {
            return is_null(input_table()[index]);
        }

        inline bool is_null(item_type item)
        {
            return std::memcmp(&item, &null_value_, bytes_per_item) == 0;
        }

    protected:
        // the table that holds all the input data
        std::vector<item_type> input_table_;

        // hashing seed
        u64 loc_func_seed_;

        // log2 of the number of cuckoo slots.
        u64 log_table_size_;

        // length of an input item in bits
        u64 raw_item_bit_length_;

        // the maximum number of attempts that are made to insert an item
        u64 max_probe_;

        // the sentenal value which denotes the current location as empty.
        item_type null_value_;

        // Source of random bits.
        std::random_device rd_;
    };

    class Cuckoo : public CuckooInterface
    {
    public:
        Cuckoo(u64 loc_func_count, u64 loc_func_seed, u64 log_table_size, 
            u64 item_bit_length, u64 max_probe, item_type null_item);

        /*
        Insertion of an element using random-walk cuckoo hashing
        */
        inline bool insert(item_type item) override 
        {
            return insert(item, 0);
        }

        u64 get_location(item_type item, u64 loc_func_index) override 
        {
            return loc_funcs_[loc_func_index].location(item);
        }

        void clear_hash_table() override;

        const std::vector<item_type> &get_encodings() override 
        { 
            return input_table_; 
        }

        u64 encoding_bit_length() const override 
        { 
            return raw_item_bit_length_; 
        }

        u64 loc_func_count() const override 
        { 
            return loc_funcs_.size(); 
        }

    private:
        void gen_loc_funcs(u64 seed);

        // Insertion of an element using random-walk cuckoo hashing
        bool insert(item_type item, u64 level);

        item_type swap(item_type item, u64 location);

        std::vector<LocFunc> loc_funcs_;
    };

    // class PermutationBasedCuckoo : public CuckooInterface
    // {
    // public:
    //     PermutationBasedCuckoo(u64 loc_func_count, u64 loc_func_seed,
    //         u64 log_table_size, u64 item_bit_length, u64 max_probe, 
    //         item_type null_item);

    //     /*
    //     Insertion of an element using random-walk cuckoo hashing
    //     */
    //     inline bool insert(item_type item) override
    //     {
    //         return insert(item, 0);
    //     }

    //     inline u64 get_location(item_type item, u64 loc_func_index) override 
    //     {
    //         return loc_funcs_[loc_func_index].location(item);
    //     }

    //     void clear_hash_table() override;

    //     const std::vector<item_type> &get_encodings() override;

    //     u64 encoding_bit_length() const override 
    //     { 
    //         return encoder_.encoding_bit_length_; 
    //     }

    //     u64 loc_func_count() const override 
    //     { 
    //         return loc_funcs_.size(); 
    //     }

    //     struct Encoder
    //     {
    //         Encoder(u64 log_table_size, u64 loc_func_count, u64 input_bit_count)
    //         {
    //             auto index_bit_count = get_significant_bit_count(loc_func_count - 1);
    //             encode_shift_length_ = log_table_size - index_bit_count;

    //             set_block(-1, -1, &encode_mask_);
    //             encode_mask_ = shift_left(encode_mask_, index_bit_count);

    //             if (log_table_size < index_bit_count)
    //             {
    //                 throw std::runtime_error("phasing is worse than normal Cuckoo due to too many hash functions");
    //             }

    //             encoding_bit_length_ = input_bit_count - log_table_size + index_bit_count;
    //         }

    //         item_type encode(item_type item, u64 loc_func_index, bool print = false);

    //         // the number of bits that we need to shift xL so that we have just 
    //         // enough bits to write the index at the bottom.
    //         u64 encode_shift_length_;

    //         u64 encoding_bit_length_;

    //         item_type encode_mask_;
    //     };

    // private:
    //     void gen_loc_funcs(u64 seed);

    //     // Insertion of an element using random-walk cuckoo hashing
    //     bool insert(item_type item, u64 level);

    //     item_type swap(item_type item, u64 table_location, u64 hash_idx);

    //     std::vector<u8> hash_index_table_;

    //     Encoder encoder_;

    //     std::vector<LocFunc> loc_funcs_;
    // };

    // /*
    //  * This is a Cuckoo hash with stash.
    //  *
    //  * The Cuckoo hash parameters can be generated by calling the function 
    //  * getHashTableSize(u64 nItems, u64& hashTableSize, u64& stashSize, u64& maxProbe, u64& nFunctions).
    //  */
    // class CuckooWithStash
    // {
    // public:
    //     /*
    //      * loc_func_count is the number of simple hash functions
    //      * loc_func_seed is a random seed to generate random hash functions
    //      * capacity is the size of the Cuckoo hash table
    //      * item_bit_length is the bit length of an item
    //      * max_probe is the maximum number of kick-outs
    //      * stash_size is the size of stash
    //      * construct_hash_table indicates whether to construct a hash table or not (in PSI one party does not need to construct the hash table)
    //      */
    //     CuckooWithStash(u64 loc_func_count, u64 loc_func_seed, u64 capacity, u64 item_bit_length, 
    //         u64 max_probe, u64 stash_size, bool construct_hash_table = true);

    //     ~CuckooWithStash();

    //     bool query_item(item_type item);

    //     /*
    //     Insertion of an element using random-walk cuckoo hashing
    //     */
    //     inline bool insert(item_type item)
    //     {
    //         return insert(item, 0);
    //     }

    //     void get_locations(item_type item, std::vector<u64> &locations);

    //     void clear_hash_table();

    //     inline void set_null(u64 index)
    //     {

    //         copy_uint(null_value_, hash_table_ + bin_u64_length_ * index, bin_u64_length_);
    //     }

    //     inline bool is_null(u64 index)
    //     {
    //         return are_equal_uint(hash_table_ + bin_u64_length_ * index, null_value_, bin_u64_length_);
    //     }

    //     /*
    //     Basic getters
    //     */
    //     inline const u64 *hash_table() const
    //     {
    //         return hash_table_;
    //     }

    //     inline const u64 *stash_table() const
    //     {
    //         return stash_table_;
    //     }

    //     inline const u64 *hash_table_item(u64 index) const
    //     {
    //         return hash_table_ + index * bin_u64_length_;
    //     }

    //     inline const u64 *stash_table_item(u64 index) const
    //     {
    //         return stash_table_ + index * bin_u64_length_;
    //     }

    //     inline u64 loc_func_count() const
    //     {
    //         return loc_func_count_;
    //     }

    //     inline u64 loc_func_seed() const
    //     {
    //         return loc_func_seed_;
    //     }

    //     inline u64 capacity() const
    //     {
    //         return capacity_;
    //     }

    //     inline u64 current_stash_size() const
    //     {
    //         return current_stash_size_;
    //     }

    //     inline u64 bin_bit_length() const
    //     {
    //         return bin_bit_length_;
    //     }

    //     inline u64 bin_u64_length() const
    //     {
    //         return bin_u64_length_;
    //     }

    //     inline u64 max_probe() const
    //     {
    //         return max_probe_;
    //     }

    //     inline const u64 *null_value() const
    //     {
    //         return null_value_;
    //     }

    // private:
    //     void gen_loc_funcs(u64 seed);

    //     inline u64 *mutable_hash_table_item(u64 index) const
    //     {
    //         return hash_table_ + index * bin_u64_length_;
    //     }

    //     // Insertion of an element using random-walk cuckoo hashing
    //     bool insert(const u64 *item, u64 level);

    //     u64 *hash_table_;

    //     std::vector<LocFuncWithStash> loc_funcs_;

    //     u64 loc_func_count_;

    //     u64 loc_func_seed_;

    //     u64 capacity_;

    //     u64 item_bit_length_;

    //     u64 bin_bit_length_;

    //     u64 item_u64_length_;

    //     u64 bin_u64_length_;

    //     u64 max_probe_;

    //     u64 *null_value_;

    //     std::random_device rd_;

    //     u64 stash_size_;

    //     u64 current_stash_size_;

    //     u64 *stash_table_;
    // };





    // inline u64 getStashSize(u64 n)
    // {
    //     if (n >= (1 << 24))
    //         return 2;
    //     if (n >= (1 << 20))
    //         return 3;
    //     if (n >= (1 << 16))
    //         return 4;
    //     if (n >= (1 << 12))
    //         return 6;
    //     if (n >= (1 << 8))
    //         return 12;

    //     return 12; //other
    // }

    // inline u64 getMaxProbe(u64 n)
    // {
    //     return n;
    // }

    // /*
    //  * This function generates the parameters for the Cuckoo hash.
    //  * nItems is the total number of items that are inserted to the Cuckoo hash
    //  * hashTableSize is the size of the Cuckoo hash table
    //  * stashSize is the size of the stash
    //  * maxProbe is the maximum number of kick-outs
    //  * nFunctions is the number of simple hash functions
    //  */
    // inline void getHashTableSize(u64 nItems, u64& hashTableSize, u64& stashSize, u64& maxProbe, u64& nFunctions)
    // {
    //     hashTableSize = 1.2 * nItems;
    //     stashSize = getStashSize(nItems);
    //     maxProbe = getMaxProbe(nItems);
    //     nFunctions = 3;
    // }
}