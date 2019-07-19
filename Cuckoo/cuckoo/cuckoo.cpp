// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#include <stdexcept>
#include <vector>
#include <utility>
#include <cassert>
#include <memory>
#include "cuckoo/cuckoo.h"

using namespace std;

namespace cuckoo
{
    QueryResult CuckooInterface::query_item(item_type item)
    {
        auto cc = loc_func_count();
        for (u64 i = 0; i < cc; i++)
        {
            auto location = get_location(item, i);
            if (memcmp(input_table().data() + location, &item, bytes_per_item) == 0)
            {
                return { location, i };
            }
        }
        return {};
    }

    Cuckoo::Cuckoo(u64 loc_func_count, u64 loc_func_seed, u64 log_table_size,
        u64 item_bit_length, u64 max_probe, item_type null_item)
    {
        loc_funcs_.resize(loc_func_count);
        loc_func_seed_ = loc_func_seed;
        log_table_size_ = log_table_size;
        raw_item_bit_length_ = item_bit_length;
        max_probe_ = max_probe;

        if (log_table_size_ > max_log_table_size || log_table_size_ > item_bit_length)
        {
            throw invalid_argument("log_table_size too large");
        }

        // Allocate empty value
        null_value_ = null_item;

        // Allocate the hash table
        input_table_.resize(1ULL << log_table_size_, null_value_);
        gen_loc_funcs(loc_func_seed_);
    }

    void Cuckoo::clear_hash_table()
    {
        auto cap = input_table_.size();
        input_table_.resize(0);
        input_table_.resize(cap, null_value_);
    }

    void Cuckoo::gen_loc_funcs(u64 seed)
    {
        for (std::size_t i = 0; i < loc_funcs_.size(); i++)
        {
            loc_funcs_[i] = LocFunc(log_table_size_, seed + i);
        }
    }

    bool Cuckoo::insert(item_type item, u64 level)
    {
        if (level >= max_probe_)
        {
            return false;
        }

        // Choose random location index
        u64 loc_index = (rd_() % loc_funcs_.size());

        u64 loc = loc_funcs_[loc_index].location(item);
        auto old_item = swap(item, loc);

        if (is_null(old_item))
        {
            return true;
        }
        else
        {
            return insert(old_item, level + 1);
        }
    }

    item_type Cuckoo::swap(item_type item, u64 location)
    {
        auto tt = input_table_[location];
        input_table_[location] = item;

        return tt;
    }

    // PermutationBasedCuckoo::PermutationBasedCuckoo(u64 loc_func_count, u64 loc_func_seed,
    //     u64 log_capacity, u64 item_bit_length, u64 max_probe, item_type null_item)
    //     :encoder_(log_capacity, loc_func_count, item_bit_length)
    // {
    //     loc_funcs_.resize(loc_func_count);
    //     loc_func_seed_ = (loc_func_seed);
    //     log_capacity_ = (log_capacity);
    //     raw_item_bit_length_ = (item_bit_length);
    //     max_probe_ = (max_probe);

    //     if (log_capacity_ > max_log_capacity || log_capacity_ > item_bit_length)
    //     {
    //         throw invalid_argument("log_capacity too large");
    //     }

    //     // Allocate empty value
    //     null_value_ = null_item;
    //     //null_encoding_ = encoder_.encode(null_item, -1);

    //     // Allocate the hash table
    //     input_table_.resize(1ull << log_capacity, null_value_);
    //     hash_index_table_.resize(input_table_.size());
    //     gen_loc_funcs(loc_func_seed_);
    // }

    // void PermutationBasedCuckoo::clear_hash_table()
    // {
    //     // Delete table tails
    //     encoded_table_.resize(0);

    //     input_table_.resize(0);
    //     input_table_.resize(hash_index_table_.size(), null_value_);
    // }

    // const std::vector<item_type>& PermutationBasedCuckoo::get_encodings()
    // {
    //     if (encoded_table_.size() == 0)
    //     {
    //         encoded_table_.resize(input_table_.size());

    //         for (auto i = 0; i < encoded_table_.size(); ++i)
    //         {
    //             encoded_table_[i] = encoder_.encode(input_table_[i], hash_index_table_[i]);
    //         }
    //     }

    //     return encoded_table_;
    // }


    // bool PermutationBasedCuckoo::insert(const item_type & item, u64 level)
    // {
    //     if (level >= max_probe_)
    //     {
    //         return false;
    //     }

    //     // Choose random location index
    //     u64 loc_index = (rd_() % loc_funcs_.size());

    //     u64 loc = loc_funcs_[loc_index].location(item);

    //     auto old_item = swap(item, loc, loc_index);

    //     if (is_null(old_item))
    //     {
    //         return true;
    //     }
    //     else
    //     {
    //         return insert(old_item, level + 1);
    //     }
    // }

    // item_type PermutationBasedCuckoo::swap(const item_type & item, u64 table_location, u64 hash_idx)
    // {
    //     auto tt = input_table_[table_location];
    //     input_table_[table_location] = item;
    //     hash_index_table_[table_location] = hash_idx;

    //     if (encoded_table_.size())
    //     {
    //         encoded_table_[table_location] = encoder_.encode(item, hash_idx);
    //     }

    //     return tt;
    // }

    // item_type PermutationBasedCuckoo::Encoder::encode(const item_type & item, u64 hash_idx, bool print)
    // {
    //     //oc::ostreamLock out(std::cout);
    //     //if(print) out << "input " << oc::BitVector((oc::u8*)&item, 128) << std::endl;

    //     // shift the top bits down so that we have just enough room to write the hash index
    //     item_type ret = shift_right(item, encode_shift_length_);

    //     //if (print) out << "shift " << oc::BitVector((oc::u8*)&ret, 128) << " < " << encode_shift_length_ << std::endl;
    //     // clear the bottom bits so we can write the hash index
    //     ret = _mm_and_si128(ret, encode_mask_);

    //     //if (print) out << "clear " << oc::BitVector((oc::u8*)&ret, 128) << std::endl;

    //     // write the hash index to the bottom bits.
    //     ret =  _mm_or_si128(ret, set_block(hash_idx, 0));

    //     //if (print) out << "or    " << oc::BitVector((oc::u8*)&ret, 128) << "   " << hash_idx << std::endl;

    //     return ret;
    // }


    // void PermutationBasedCuckoo::gen_loc_funcs(u64 seed)
    // {
    //     for (int i = 0; i < loc_funcs_.size(); i++)
    //     {
    //         loc_funcs_[i] = PermutationBasedLocFunc(log_capacity_, seed + i);
    //     }
    // }

    // //
    // //bool PermutationBasedCuckoo::insert(const u64 *item, u64 level)
    // //{
    // //	if (locked_)
    // //	{
    // //		throw logic_error("table is locked");
    // //	}

    // //	if (level >= max_probe_)
    // //	{
    // //		return false;
    // //	}

    // //	// Allocate temp_item
    // //	// We assume bin_u64_length_ == item_u64_length_
    // //	unique_ptr<u64> temp_item(new u64[bin_u64_length_]);
    // //	zero_uint(temp_item.get(), bin_u64_length_);

    // //	vector<u64> locations_vec;
    // //	get_locations(item, locations_vec);

    // //	// Choose random location index
    // //	u64 loc_index = (rd_() % loc_funcs_.size());
    // //	u64 loc = locations_vec[loc_index];

    // //	if (is_null(loc))
    // //	{
    // //		// Insert new value
    // //		copy_uint(item, mutable_hash_table_item(loc), bin_u64_length_);

    // //		// Append location index
    // //		append_loc_index(mutable_hash_table_item(loc), loc_index);

    // //		return true;
    // //	}

    // //	// Store old value and insert new
    // //	copy_uint(hash_table_item(loc), temp_item.get(), bin_u64_length_);
    // //	copy_uint(item, mutable_hash_table_item(loc), bin_u64_length_);

    // //	// Append new location index to inserted value overwriting old
    // //	append_loc_index(mutable_hash_table_item(loc), loc_index);

    // //	// Clear location index from previous value
    // //	append_loc_index(temp_item.get(), 0);
    // //	
    // //	return insert(temp_item.get(), level + 1);
    // //}

    // //bool PermutationBasedCuckoo::query_item(const u64 *item)
    // //{
    // //	if (!locked_)
    // //	{
    // //		throw logic_error("hash table is not locked");
    // //	}

    // //	vector<u64> locs;
    // //	get_locations(item, locs);

    // //	u64 shifted_bin_u64_length = (bin_bit_length_ - log_capacity_ + 63) / 64;
    // //	unique_ptr<u64> temp_item(new u64[bin_u64_length_]);
    // //	right_shift_uint(item, temp_item.get(), log_capacity_, bin_u64_length_);
    // //	zero_uint(temp_item.get() + shifted_bin_u64_length, bin_u64_length_ - shifted_bin_u64_length);
    // //	u64 *shifted_item_top_ptr = temp_item.get() + shifted_bin_u64_length - 1;
    // //	u64 top_u64_mask = (static_cast<u64>(1) << ((item_bit_length_ - log_capacity_) % 64)) - 1;

    // //	for (int i = 0; i < locs.size(); i++)
    // //	{
    // //		/*
    // //		Instead of appending location index as usual (append_loc_index)
    // //		we append it to the shifted string, which is why we have a special
    // //		purpose logic here.
    // //		*/
    // //		// append_loc_index(temp_item.get(), i);
    // //		*shifted_item_top_ptr &= top_u64_mask;
    // //		*shifted_item_top_ptr ^= (static_cast<u64>(i) << ((item_bit_length_ - log_capacity_) % 64));

    // //		if (are_equal_uint(hash_table_item(locs[i]), temp_item.get(), bin_u64_length_))
    // //		{
    // //			return true;
    // //		}
    // //	}
    // //	return false;
    // //}





    // CuckooWithStash::CuckooWithStash(u64 loc_func_count, u64 loc_func_seed, u64 capacity, u64 item_bit_length, u64 max_probe, u64 stash_size, bool construct_hash_table)
    //     : loc_func_count_(loc_func_count),
    //     loc_func_seed_(loc_func_seed),
    //     capacity_(capacity), item_bit_length_(item_bit_length),
    //     bin_bit_length_(item_bit_length + 1), max_probe_(max_probe),
    //     stash_size_(stash_size), current_stash_size_(0),
    //     hash_table_(nullptr), null_value_(nullptr), stash_table_(nullptr)
    // {

    //     item_u64_length_ = (item_bit_length_ + 63) / 64;
    //     bin_u64_length_ = (bin_bit_length_ + 63) / 64;

    //     // Allocate empty value
    //     null_value_ = new u64[bin_u64_length_];
    //     zero_uint(null_value_, bin_u64_length_);
    //     *null_value_ = 1;
    //     left_shift_uint(null_value_, null_value_, bin_bit_length_ - 1, bin_u64_length_);

    //     // Allocate the hash table
    //     if (construct_hash_table)
    //     {
    //         hash_table_ = new u64[bin_u64_length_ * capacity_];
    //         clear_hash_table();
    //         if (stash_size_)
    //         {
    //             stash_table_ = new u64[bin_u64_length_ * stash_size_];
    //         }
    //     }

    //     gen_loc_funcs(loc_func_seed_);
    // }

    // CuckooWithStash::~CuckooWithStash()
    // {
    //     if (hash_table_ != nullptr)
    //     {
    //         delete[] hash_table_;
    //         hash_table_ = nullptr;
    //     }
    //     if (null_value_ != nullptr)
    //     {
    //         delete[] null_value_;
    //         null_value_ = nullptr;
    //     }

    //     if (stash_table_ != nullptr)
    //     {
    //         delete[] stash_table_;
    //         stash_table_ = nullptr;
    //     }
    // }

    // void CuckooWithStash::clear_hash_table()
    // {
    //     u64 *item_ptr = hash_table_;
    //     for (u64 i = 0; i < capacity_; i++)
    //     {
    //         set_null(i);
    //     }
    // }

    // void CuckooWithStash::gen_loc_funcs(u64 seed)
    // {
    //     loc_funcs_.clear();
    //     for (int i = 0; i < loc_func_count_; i++)
    //     {
    //         loc_funcs_.emplace_back(capacity_, item_u64_length_, seed + i);
    //     }
    // }

    // void CuckooWithStash::get_locations(const u64 *item, vector<u64> &locations)
    // {
    //     locations.clear();
    //     for (int i = 0; i < loc_func_count_; i++)
    //     {
    //         locations.emplace_back(loc_funcs_[i].location(item));
    //     }
    // }

    // bool CuckooWithStash::insert(const u64 *item, u64 level)
    // {
    //     if (level >= max_probe_)
    //     {
    //         if (current_stash_size_ < stash_size_)
    //         {
    //             copy_uint(item, stash_table_ + bin_u64_length_ * (current_stash_size_++), bin_u64_length_);
    //             return true;
    //         }
    //         return false;
    //     }

    //     // Allocate temp_item
    //     // We assume bin_u64_length_ == item_u64_length_
    //     unique_ptr<u64> temp_item(new u64[bin_u64_length_]);
    //     zero_uint(temp_item.get(), bin_u64_length_);

    //     // Choose random location index
    //     u64 loc_index = (rd_() % loc_func_count_);

    //     u64 loc = loc_funcs_[loc_index].location(item);

    //     if (is_null(loc))
    //     {
    //         // Insert new value
    //         copy_uint(item, mutable_hash_table_item(loc), bin_u64_length_);
    //         return true;
    //     }

    //     // Store old value and insert new
    //     copy_uint(hash_table_item(loc), temp_item.get(), bin_u64_length_);
    //     copy_uint(item, mutable_hash_table_item(loc), bin_u64_length_);

    //     return insert(temp_item.get(), level + 1);
    // }

    // bool CuckooWithStash::query_item(const u64 *item)
    // {
    //     vector<u64> locs;
    //     get_locations(item, locs);
    //     for (int i = 0; i < locs.size(); i++)
    //     {
    //         if (are_equal_uint(hash_table_item(locs[i]), item, bin_u64_length_))
    //         {
    //             return true;
    //         }
    //     }
    //     for (auto i = 0; i < current_stash_size_; ++i)
    //     {
    //         if (are_equal_uint(stash_table_item(i), item, bin_u64_length_))
    //         {
    //             return true;
    //         }
    //     }
    //     return false;
    // }
}