// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <random>
#include <stdexcept>

// APSI
#include "apsi/util/cuckoo_filter_table.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace apsi::util;
using namespace apsi::sender::util;

namespace {
    struct TagIndexInfo {
        size_t tag_start_idx;
        size_t tag_start_offset;
        size_t bits_first_word;
        size_t bits_second_word = 0;

        /**
        Compute the necessary indexes and bit positions to locate a tag position
        within an array of uint64_t
        */
        TagIndexInfo(size_t bits_per_tag, size_t tags_per_bucket, size_t bucket, size_t tag_idx)
            : bits_first_word(bits_per_tag)
        {
            size_t tag_start_bit =
                (bucket * bits_per_tag * tags_per_bucket) + (tag_idx * bits_per_tag);
            tag_start_idx = tag_start_bit / 64;
            tag_start_offset = tag_start_bit % 64;

            if (tag_start_offset > 64 - bits_per_tag) {
                bits_first_word = 64 - tag_start_offset;
                bits_second_word = bits_per_tag - bits_first_word;
            }
        }
    };
} // namespace

CuckooFilterTable::CuckooFilterTable(
    vector<uint64_t> table, size_t num_buckets, size_t bits_per_tag)
    : bits_per_tag_(bits_per_tag), table_(std::move(table)), num_buckets_(num_buckets)
{
    // 64 is excluded along with 0: the tag mask below shifts by bits_per_tag, and a shift by the
    // full width of the type is undefined. Nothing here needs a tag that wide.
    if (bits_per_tag == 0 || bits_per_tag >= 64) {
        throw invalid_argument("bits_per_tag must be between 1 and 63");
    }
    // The alternate bucket for a tag is found by masking with num_buckets - 1, which only reaches
    // every bucket when num_buckets is a power of two. The sizing constructor produces one, so a
    // table that does not have one did not come from this class.
    if (num_buckets == 0 || next_power_of_2(num_buckets) != num_buckets) {
        throw invalid_argument("num_buckets must be a nonzero power of two");
    }

    // The table must be exactly the size these parameters call for. Every read and write below
    // bounds the bucket against num_buckets_ and then indexes table_ at a position derived from
    // it, so a table smaller than num_buckets_ calls for turns those bounds checks into no-ops
    // and indexes past the end of the vector. This constructor takes all three from whatever
    // produced them, which for CuckooFilter::Load is a serialized filter that may be hostile.
    //
    // The multiplication is checked because num_buckets is not: bits_per_bucket is at most 256,
    // so a num_buckets above 2^56 would wrap and yield a small required size that almost any
    // table satisfies.
    size_t bits_per_bucket = tags_per_bucket_ * bits_per_tag;
    size_t required_words = 0;
    try {
        required_words =
            seal::util::add_safe(
                seal::util::mul_safe(bits_per_bucket, num_buckets), static_cast<size_t>(63)) /
            64;
    } catch (const logic_error &) {
        throw invalid_argument("num_buckets is too large for bits_per_tag");
    }
    if (table_.size() != required_words) {
        throw invalid_argument("table size does not match num_buckets and bits_per_tag");
    }

    // This is used to check that tags are not too big
    tag_input_mask_ = ~static_cast<uint64_t>(0) << bits_per_tag;
}

CuckooFilterTable::CuckooFilterTable(size_t num_items, size_t bits_per_tag)
    : bits_per_tag_(bits_per_tag)
{
    // 64 is excluded along with 0: the tag mask below shifts by bits_per_tag, and a shift by the
    // full width of the type is undefined. Nothing here needs a tag that wide.
    if (bits_per_tag == 0 || bits_per_tag >= 64) {
        throw invalid_argument("bits_per_tag must be between 1 and 63");
    }

    // This is used to check that tags are not too big
    tag_input_mask_ = ~static_cast<uint64_t>(0) << bits_per_tag;

    num_buckets_ = next_power_of_2(max<uint64_t>(1, num_items / tags_per_bucket_));
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
    size_t num_uint64 = ((bits_per_bucket * num_buckets_) + 63) / 64;
    table_.resize(num_uint64);
}

uint64_t CuckooFilterTable::read_tag(size_t bucket, size_t tag_idx) const
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
    uint64_t tag = (tag_word >> tii.tag_start_offset) & mask;

    if (tii.bits_second_word != 0) {
        // The tag needs to be completed with the next uint64_t
        tag_word = table_[tii.tag_start_idx + 1];
        mask = ~(~static_cast<uint64_t>(0) << tii.bits_second_word);
        tag |= (tag_word & mask) << tii.bits_first_word;
    }

    return tag;
}

void CuckooFilterTable::write_tag(size_t bucket, size_t tag_idx, uint64_t tag)
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

    uint64_t tag_ones = ~tag_input_mask_;
    uint64_t tag_mask = ~(tag_ones << tii.tag_start_offset);
    uint64_t tag_word = tag << tii.tag_start_offset;
    table_[tii.tag_start_idx] &= tag_mask;
    table_[tii.tag_start_idx] |= tag_word;

    if (tii.bits_second_word != 0) {
        // Write the rest of the tag to the next uint64_t
        tag_mask = ~(tag_ones >> tii.bits_first_word);
        tag_word = tag >> tii.bits_first_word;
        table_[tii.tag_start_idx + 1] &= tag_mask;
        table_[tii.tag_start_idx + 1] |= tag_word;
    }
}

bool CuckooFilterTable::insert_tag(size_t bucket, uint64_t tag, bool kickout, uint64_t &old_tag)
{
    for (size_t i = 0; i < tags_per_bucket_; i++) {
        if (read_tag(bucket, i) == 0) {
            write_tag(bucket, i, tag);
            return true;
        }
    }

    if (kickout) {
        // Pick a victim slot to evict. The randomness quality is unimportant, so a thread-local
        // Mersenne Twister with a fixed seed suffices; unlike rand() it is thread-safe. A fixed
        // seed is intentional (deterministic, reproducible eviction; no security relevance here).
        // NOLINTNEXTLINE(bugprone-random-generator-seed)
        static thread_local std::mt19937 gen(/* seed */ 0);
        size_t rnd_idx = static_cast<size_t>(gen()) % tags_per_bucket_;
        old_tag = read_tag(bucket, rnd_idx);
        write_tag(bucket, rnd_idx, tag);
    }

    return false;
}

bool CuckooFilterTable::delete_tag(size_t bucket, uint64_t tag)
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

bool CuckooFilterTable::find_tag_in_bucket(size_t bucket, uint64_t tag) const
{
    if (bucket >= num_buckets_) {
        throw invalid_argument("bucket out of range");
    }
    if (tag & tag_input_mask_) {
        throw invalid_argument("tag is not constrained to bits_per_tag");
    }

    for (size_t i = 0; i < tags_per_bucket_; i++) {
        if (read_tag(bucket, i) == tag) {
            return true;
        }
    }

    return false;
}

bool CuckooFilterTable::find_tag_in_buckets(size_t bucket1, size_t bucket2, uint64_t tag) const
{
    if (bucket1 >= num_buckets_) {
        throw invalid_argument("bucket1 out of range");
    }
    if (bucket2 >= num_buckets_) {
        throw invalid_argument("bucket2 out of range");
    }

    if (find_tag_in_bucket(bucket1, tag)) {
        return true;
    }
    if (find_tag_in_bucket(bucket2, tag)) {
        return true;
    }

    return false;
}
