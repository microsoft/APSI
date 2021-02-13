// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <stdexcept>

// APSI
#include "cuckoo_filter_table.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace apsi::util;
using namespace apsi::sender::util;

namespace {
    struct TagIndexInfo {
        size_t tag_start_bit;
        size_t tag_start_idx;
        size_t tag_start_offset;
        size_t bits_first_word;
        size_t bits_second_word;

        TagIndexInfo(size_t bits_per_tag, size_t tags_per_bucket, size_t bucket, size_t tag_idx)
        {
            tag_start_bit = (bucket * bits_per_tag * tags_per_bucket) + (tag_idx * bits_per_tag);
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
}

CuckooFilterTable::CuckooFilterTable(size_t num_items, size_t bits_per_tag)
    : bits_per_tag_(bits_per_tag), tag_input_mask_(static_cast<std::uint32_t>(-1) << bits_per_tag)
{
    num_buckets_ = next_power_of_2(std::max<uint64_t>(1, num_items / tags_per_bucket_));

    // Round up to the nearest uint64_t
    size_t bits_per_bucket = tags_per_bucket_ * bits_per_tag;
    size_t num_uint64 = (bits_per_bucket * num_buckets_ + 63) / 64;
    table_.resize(num_uint64);
}

uint32_t CuckooFilterTable::read_tag(size_t bucket, size_t tag_idx) const
{
    TagIndexInfo tii(bits_per_tag_, tags_per_bucket_, bucket, tag_idx);

    uint64_t tag_word = table_[tii.tag_start_idx];
    uint64_t mask = ~(static_cast<uint64_t>(-1) << tii.bits_first_word);
    uint32_t tag = static_cast<uint32_t>((tag_word >> tii.tag_start_offset) & mask);

    if (tii.bits_second_word != 0) {
        tag_word = table_[tii.tag_start_idx + 1];
        mask = ~(static_cast<uint64_t>(-1) << tii.bits_second_word);
        tag |= (static_cast<uint32_t>(tag_word) & mask) << tii.bits_first_word;
    }

    return tag;
}

void CuckooFilterTable::write_tag(size_t bucket, size_t tag_idx, uint32_t tag)
{
    if (tag & tag_input_mask_) {
        throw invalid_argument("tag is not constrained to bits_per_tag");
    }

    TagIndexInfo tii(bits_per_tag_, tags_per_bucket_, bucket, tag_idx);

    uint64_t tag_ones = (1ull << (bits_per_tag_ + 1)) - 1;
    uint64_t tag_mask = ~(tag_ones << tii.tag_start_offset);
    uint64_t tag_word = static_cast<uint64_t>(tag) << tii.tag_start_offset;
    table_[tii.tag_start_idx] &= tag_mask;
    table_[tii.tag_start_idx] |= tag_word;

    if (tii.bits_second_word != 0) {
        tag_mask = ~(tag_ones >> tii.bits_first_word);
        tag_word = static_cast<uint64_t>(tag) >> tii.bits_first_word;
        table_[tii.tag_start_idx + 1] &= tag_mask;
        table_[tii.tag_start_idx + 1] |= tag_word;
    }
}
