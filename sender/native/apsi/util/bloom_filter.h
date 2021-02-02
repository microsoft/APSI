// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <vector>

// APSI
#include "hash.h"
#include "apsi/util/db_encoding.h"

namespace apsi {
namespace sender {
namespace util {

    /**
    Bloom filter
    */
    class BloomFilter {
    public:
        /**
        Construct a BloomFilter instance
        */
        BloomFilter(int max_bin_size, std::size_t size_ratio = 0);

        /**
        Creates a new BloomFilter by moving a given one.
        */
        BloomFilter(BloomFilter &&filter) = default;

        /**
        Creates a new BloomFilter by copying a given one.
        */
        BloomFilter(const BloomFilter &filter) = default;

        /**
        Add a field element to the bloom filter
        */
        void add(const apsi::util::felt_t &elem);

        /**
        Determine whether a field element is possibly contained in the bloom filter
        */
        bool maybe_present(const apsi::util::felt_t &elem) const;

        /**
        Clear all bits in the filter
        */
        void clear();

    private:
        static constexpr std::size_t hash_func_count_ = 4;
        
        static constexpr std::size_t default_size_ratio_ = 10;

        static const std::vector<HashFunc> &hash_funcs();

        std::vector<bool> bits_;

        std::size_t compute_idx(const size_t hash_idx, const apsi::util::felt_t &elem) const;
    };

} // namespace util
} // namespace sender
} // namespace apsi
