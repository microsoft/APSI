// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "bloom_filter.h"

// SEAL
#include "seal/randomgen.h"

using namespace std;
using namespace seal;
using namespace apsi::util;

namespace apsi {
namespace sender {
namespace util {

    vector<HashFunc> BloomFilter::hash_funcs_;

    BloomFilter::BloomFilter(int max_bin_size, size_t size_ratio)
    {
        auto factory = UniformRandomGeneratorFactory::DefaultFactory();
        auto prng = factory->create();

        if (hash_funcs_.size() == 0) {
            hash_funcs_.resize(hash_func_count_);

            for (size_t i = 0; i < hash_funcs_.size(); i++) {
                uint64_t hfunc_seed = 0;
                prng->generate(sizeof(uint64_t), reinterpret_cast<seal::seal_byte*>(&hfunc_seed));

                hash_funcs_[i] = HashFunc(hfunc_seed);
            }
        }

        if (0 == size_ratio) {
            size_ratio = size_ratio_;
        }

        size_t bitarray_size = max_bin_size * size_ratio;
        bits_.resize(bitarray_size);
    }

    void BloomFilter::add(const felt_t &elem)
    {
        for (size_t i = 0; i < hash_funcs_.size(); i++) {
            auto idx = compute_idx(i, elem);

            bits_[idx] = true;
        }
    }

    bool BloomFilter::maybe_present(const felt_t &elem) const
    {
        for (size_t i = 0; i < hash_funcs_.size(); i++) {
            auto idx = compute_idx(i, elem);

            if (!bits_[idx])
                return false;
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
        auto hash = hash_funcs_[hash_idx](elem);
        hash = hash % bits_.size();

        return hash;
    }

} // namespace util
} // namespace sender
} // namespace apsi
