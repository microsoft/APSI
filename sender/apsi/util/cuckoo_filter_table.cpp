// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <stdexcept>

// APSI
#include "apsi/util/cuckoo_filter_table.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace apsi::util;
using namespace apsi::sender::util;

namespace {
    struct TagIndexInfo {
        size_t tag_start_idx;
        size_t tag_start_offset;
        size_t bits_first_word;
        size_t bits_second_word;

        /**
        Compute the necessary indexes and bit positions to locate a tag position
        within an array of uint64_t
        */
        TagIndexInfo(size_t bits_per_tag, size_t tags_per_bucket, size_t bucket, size_t tag_idx)
        {
            size_t tag_start_bit =
                (bucket * bits_per_tag * tags_per_bucket) + (tag_idx * bits_per_tag);
            tag_start_idx = tag_start_bit / 64;
            tag_start_offset = tag_start_bit % 64;
            bits_first_word = bits_per_tag;
            bits_second_word = 0;

            if (tag_start_offset > 64 - bits_per_tag) {
                bits_first_word = 64 - tag_start_offset;
                bits_second_word = bits_per_tag - bits_first_word;
            }
        }
    };
} // namespace

CuckooFilterTable::CuckooFilterTable(size_t num_items, size_t bits_per_tag)
    : bits_per_tag_(bits_per_tag), tag_input_mask_(static_cast<std::uint32_t>(-1) << bits_per_tag)
{
    num_buckets_ = next_power_of_2(std::max<uint64_t>(1, num_items / tags_per_bucket_));
    double items_to_bucket_ratio =
        static_cast<double>(num_items) /
        (static_cast<double>(num_buckets_) * static_cast<double>(tags_per_bucket_));
    if (items_to_bucket_ratio > 0.96) {
        // If the ratio is too close to 1 we might have failures trying to insert
        // the maximum number of items
        num_buckets_ *= 2;
    }

    // Round up to the nearest uint64_t
    size_t bits_per_bucket = tags_per_bucket_ * bits_per_tag;
    size_t num_uint64 = (bits_per_bucket * num_buckets_ + 63) / 64;
    table_.resize(num_uint64);
}

uint32_t CuckooFilterTable::read_tag(size_t bucket, size_t tag_idx) const
{
    if (bucket >= num_buckets_) {
        throw invalid_argument("bucket out of range");
    }
    if (tag_idx >= tags_per_bucket_) {
        throw invalid_argument("tag_idx out of range");
    }

    TagIndexInfo tii(bits_per_tag_, tags_per_bucket_, bucket, tag_idx);

    uint64_t tag_word = table_[tii.tag_start_idx];
    uint64_t mask = ~(~static_cast<uint64_t>(0) << tii.bits_first_word);
    uint32_t tag = static_cast<uint32_t>((tag_word >> tii.tag_start_offset) & mask);

    if (tii.bits_second_word != 0) {
        // The tag needs to be completed with the next uint64_t
        tag_word = table_[tii.tag_start_idx + 1];
        mask = ~(~static_cast<uint64_t>(0) << tii.bits_second_word);
        tag |= (static_cast<uint32_t>(tag_word) & static_cast<uint32_t>(mask))
               << tii.bits_first_word;
    }

    return tag;
}

void CuckooFilterTable::write_tag(size_t bucket, size_t tag_idx, uint32_t tag)
{
    if (bucket >= num_buckets_) {
        throw invalid_argument("bucket out of range");
    }
    if (tag_idx >= tags_per_bucket_) {
        throw invalid_argument("tag_idx out of range");
    }
    if (tag & tag_input_mask_) {
        throw invalid_argument("tag is not constrained to bits_per_tag");
    }

    TagIndexInfo tii(bits_per_tag_, tags_per_bucket_, bucket, tag_idx);

    uint64_t tag_ones = (1ull << bits_per_tag_) - 1;
    uint64_t tag_mask = ~(tag_ones << tii.tag_start_offset);
    uint64_t tag_word = static_cast<uint64_t>(tag) << tii.tag_start_offset;
    table_[tii.tag_start_idx] &= tag_mask;
    table_[tii.tag_start_idx] |= tag_word;

    if (tii.bits_second_word != 0) {
        // Write the rest of the tag to the next uint64_t
        tag_mask = ~(tag_ones >> tii.bits_first_word);
        tag_word = static_cast<uint64_t>(tag) >> tii.bits_first_word;
        table_[tii.tag_start_idx + 1] &= tag_mask;
        table_[tii.tag_start_idx + 1] |= tag_word;
    }
}

bool CuckooFilterTable::insert_tag(size_t bucket, uint32_t tag, bool kickout, uint32_t &old_tag)
{
    for (size_t i = 0; i < tags_per_bucket_; i++) {
        if (read_tag(bucket, i) == 0) {
            write_tag(bucket, i, tag);
            return true;
        }
    }

    if (kickout) {
        size_t rnd_idx = static_cast<size_t>(rand()) % tags_per_bucket_;
        old_tag = read_tag(bucket, rnd_idx);
        write_tag(bucket, rnd_idx, tag);
    }

    return false;
}

bool CuckooFilterTable::delete_tag(std::size_t bucket, std::uint32_t tag)
{
    if (bucket >= num_buckets_) {
        throw invalid_argument("bucket out of range");
    }
    if (tag & tag_input_mask_) {
        throw invalid_argument("tag is not constrained to bits_per_tag");
    }

    for (size_t i = 0; i < tags_per_bucket_; i++) {
        if (read_tag(bucket, i) == tag) {
            write_tag(bucket, i, 0);
            return true;
        }
    }

    return false;
}

bool CuckooFilterTable::find_tag_in_bucket(std::size_t bucket, std::uint32_t tag) const
{
    if (bucket >= num_buckets_) {
        throw invalid_argument("bucket out of range");
    }
    if (tag & tag_input_mask_) {
        throw invalid_argument("tag is not constrained to bits_per_tag");
    }

    for (size_t i = 0; i < tags_per_bucket_; i++) {
        if (read_tag(bucket, i) == tag)
            return true;
    }

    return false;
}

bool CuckooFilterTable::find_tag_in_buckets(
    std::size_t bucket1, std::size_t bucket2, std::uint32_t tag) const
{
    if (bucket1 >= num_buckets_) {
        throw invalid_argument("bucket1 out of range");
    }
    if (bucket2 >= num_buckets_) {
        throw invalid_argument("bucket2 out of range");
    }

    if (find_tag_in_bucket(bucket1, tag))
        return true;
    if (find_tag_in_bucket(bucket2, tag))
        return true;

    return false;
}
