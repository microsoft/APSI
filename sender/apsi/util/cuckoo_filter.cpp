// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/util/cuckoo_filter.h"
#include "apsi/util/hash.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace apsi::util;
using namespace apsi::sender::util;

namespace {
    /**
    Hash function for the cuckoo filter.
    The seed is completely arbitrary, doesn't need to be random.
    */
    HashFunc hasher_(/* seed */ 20);
} // namespace

CuckooFilter::CuckooFilter(size_t key_count_max, size_t bits_per_tag) : num_items_(0), overflow_()
{
    overflow_.used = false;
    table_ = make_unique<CuckooFilterTable>(key_count_max, bits_per_tag);
}

bool CuckooFilter::contains(const felt_t &item) const
{
    size_t idx1, idx2;
    uint32_t tag;

    get_tag_and_index(item, tag, idx1);
    idx2 = get_alt_index(idx1, tag);

    if (overflow_.used && overflow_.tag == tag) {
        if (overflow_.index == idx1 || overflow_.index == idx2)
            return true;
    }

    return table_->find_tag_in_buckets(idx1, idx2, tag);
}

bool CuckooFilter::add(const felt_t &item)
{
    if (overflow_.used)
        return false; // No more space

    uint32_t tag;
    size_t idx;
    get_tag_and_index(item, tag, idx);

    bool result = add_index_tag(idx, tag);
    if (result) {
        num_items_++;
    }

    return result;
}

bool CuckooFilter::add_index_tag(std::size_t idx, std::uint32_t tag)
{
    size_t curr_idx = idx;
    uint32_t curr_tag = tag;
    uint32_t old_tag = 0;

    for (size_t i = 0; i < max_cuckoo_kicks_; i++) {
        bool kickout = i > 0;
        old_tag = 0;

        if (table_->insert_tag(curr_idx, curr_tag, kickout, old_tag)) {
            return true;
        }

        if (kickout) {
            curr_tag = old_tag;
        }

        curr_idx = get_alt_index(curr_idx, curr_tag);
    }

    overflow_.index = curr_idx;
    overflow_.tag = curr_tag;
    overflow_.used = true;

    return true;
}

bool CuckooFilter::remove(const felt_t &item)
{
    size_t idx1, idx2;
    uint32_t tag;

    get_tag_and_index(item, tag, idx1);
    idx2 = get_alt_index(idx1, tag);

    if (table_->delete_tag(idx1, tag)) {
        num_items_--;
        try_eliminate_overflow();
        return true;
    }

    if (table_->delete_tag(idx2, tag)) {
        num_items_--;
        try_eliminate_overflow();
        return true;
    }

    if (overflow_.used && (overflow_.index == idx1 || overflow_.index == idx2) &&
        overflow_.tag == tag) {
        overflow_.used = false;
        num_items_--;
        return true;
    }

    return false;
}

uint32_t CuckooFilter::tag_bit_limit(uint32_t value) const
{
    uint32_t mask = (1 << static_cast<uint32_t>(table_->get_bits_per_tag())) - 1;
    uint32_t tag = value & mask;
    tag += (tag == 0);
    return tag;
}

size_t CuckooFilter::idx_bucket_limit(size_t value) const
{
    size_t mask = table_->get_num_buckets() - 1;
    return value & mask;
}

void CuckooFilter::get_tag_and_index(const felt_t &item, uint32_t &tag, size_t &idx) const
{
    uint64_t hash = static_cast<uint64_t>(hasher_(item));
    idx = idx_bucket_limit(hash >> 32);
    tag = tag_bit_limit(static_cast<uint32_t>(hash));
}

size_t CuckooFilter::get_alt_index(size_t idx, uint32_t tag) const
{
    uint64_t hash = static_cast<uint64_t>(hasher_(tag));
    size_t idx_hash = idx_bucket_limit(hash);
    return idx ^ idx_hash;
}

void CuckooFilter::try_eliminate_overflow()
{
    // Try to insert the overflow item into the table.
    if (overflow_.used) {
        overflow_.used = false;
        add_index_tag(overflow_.index, overflow_.tag);
    }
}
