// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/bloom_filter.h"

#include <iostream>

using namespace std;
using namespace apsi::util;

namespace apsi {
namespace sender {
namespace util {
    BloomFilter::BloomFilter(int max_bin_size, size_t size_ratio)
    {
        if (0 == size_ratio)
        {
            size_ratio = default_size_ratio_;
        }

        size_t bitarray_size = max_bin_size * size_ratio;
        bits_.resize(bitarray_size, false);
    }

    const vector<HashFunc> &BloomFilter::hash_funcs()
    {
        static vector<HashFunc> hfs = [&]() {
            vector<HashFunc> ret;
            ret.reserve(hash_func_count_);
            for (size_t i = 0; i < hash_func_count_; i++)
            {
                uint64_t hfunc_seed = static_cast<uint64_t>(i);
                ret.emplace_back(hfunc_seed);
            }
            return ret;
        }();

        return hfs;
    }

    void BloomFilter::add(const felt_t &elem)
    {
        for (size_t i = 0; i < hash_func_count_; i++) {
            auto idx = compute_idx(i, elem);
            bits_[idx] = true;
        }
    }

    bool BloomFilter::maybe_present(const felt_t &elem) const
    {
        for (size_t i = 0; i < hash_func_count_; i++) {
            auto idx = compute_idx(i, elem);
            if (!bits_[idx])
            {
                return false;
            }
        }

        return true;
    }

    void BloomFilter::clear()
    {
        size_t size = bits_.size();
        bits_.clear();
        bits_.resize(size);
    }

    size_t BloomFilter::compute_idx(const size_t hash_idx, const felt_t &elem) const
    {
        auto hash = hash_funcs()[hash_idx](elem);
        return hash % bits_.size();
    }

} // namespace util
} // namespace sender
} // namespace apsi
