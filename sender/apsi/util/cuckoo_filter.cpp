// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/util/cuckoo_filter.h"
#include "apsi/util/cuckoo_filter_generated.h"
#include "apsi/util/hash.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace apsi::util;
using namespace apsi::sender::util;

namespace {
    /**
    Hash function for the cuckoo filter. The seed is completely arbitrary, doesn't need to be
    random. A function-local static defers the (potentially throwing) construction to first use
    rather than during dynamic initialization.
    */
    HashFunc &hasher()
    {
        static HashFunc instance(/* seed */ 20);
        return instance;
    }
} // namespace

CuckooFilter::CuckooFilter(
    CuckooFilterTable table,
    size_t table_num_items,
    size_t overflow_index,
    uint64_t overflow_tag,
    bool overflow_used,
    bool dropped_items)
    : num_items_(table_num_items), dropped_items_(dropped_items)
{
    table_ = make_unique<CuckooFilterTable>(std::move(table));

    // An overflow slot in use names a bucket and a tag, and try_eliminate_overflow hands both
    // straight to the table on the next successful removal. A bucket past the end of the table,
    // or a tag wider than the table stores, would surface there as a failure of an unrelated
    // operation rather than here, where the values arrived. A zero tag marks an empty slot, so
    // it cannot be the contents of one that is in use.
    // num_items_ is decremented on every successful removal, so a count smaller than the number
    // of tags actually present would wrap it. A table holds at most tags_per_bucket per bucket,
    // plus the one in the overflow slot.
    size_t max_num_items = (table_->get_num_buckets() * CuckooFilterTable::get_tags_per_bucket()) +
                           (overflow_used ? 1 : 0);
    if (table_num_items > max_num_items) {
        throw invalid_argument("num_items is larger than the table can hold");
    }

    if (overflow_used) {
        if (overflow_index >= table_->get_num_buckets()) {
            throw invalid_argument("overflow index is out of range");
        }
        if (overflow_tag == 0 ||
            overflow_tag >= (static_cast<uint64_t>(1) << table_->get_bits_per_tag())) {
            throw invalid_argument("overflow tag is not a valid tag");
        }
    }

    overflow_ = OverflowCache();
    overflow_.index = overflow_index;
    overflow_.tag = overflow_tag;
    overflow_.used = overflow_used;
}

CuckooFilter::CuckooFilter(size_t key_count_max, size_t bits_per_tag) : num_items_(0), overflow_()
{
    overflow_.used = false;
    table_ = make_unique<CuckooFilterTable>(key_count_max, bits_per_tag);
}

bool CuckooFilter::contains(gsl::span<const uint64_t> item) const
{
    size_t idx1;
    size_t idx2;
    uint64_t tag = 0;

    get_tag_and_index(item, tag, idx1);
    idx2 = get_alt_index(idx1, tag);

    if (overflow_.used && overflow_.tag == tag) {
        if (overflow_.index == idx1 || overflow_.index == idx2) {
            return true;
        }
    }

    return table_->find_tag_in_buckets(idx1, idx2, tag);
}

bool CuckooFilter::add(gsl::span<const uint64_t> item)
{
    if (overflow_.used) {
        // No more space. Remember it: the item is not recorded anywhere, so this filter no
        // longer knows everything it was asked to hold.
        dropped_items_ = true;
        return false;
    }

    uint64_t tag = 0;
    size_t idx = 0;
    get_tag_and_index(item, tag, idx);

    bool result = add_index_tag(idx, tag);
    if (result) {
        num_items_++;
    }

    return result;
}

bool CuckooFilter::add_index_tag(size_t idx, uint64_t tag)
{
    size_t curr_idx = idx;
    uint64_t curr_tag = tag;
    uint64_t old_tag = 0;

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

    // We only call this function when we know that overflow is not used
    overflow_.index = curr_idx;
    overflow_.tag = curr_tag;
    overflow_.used = true;

    return true;
}

bool CuckooFilter::remove(gsl::span<const uint64_t> item)
{
    size_t idx1;
    size_t idx2;
    uint64_t tag = 0;

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

uint64_t CuckooFilter::tag_bit_limit(uint64_t value) const
{
    size_t bits_per_tag = table_->get_bits_per_tag();
    uint64_t mask = ~static_cast<uint64_t>(0) >> (64 - bits_per_tag);
    uint64_t tag = value & mask;
    tag += (tag == 0);
    return tag;
}

size_t CuckooFilter::idx_bucket_limit(size_t value) const
{
    size_t mask = table_->get_num_buckets() - 1;
    return value & mask;
}

void CuckooFilter::get_tag_and_index(
    gsl::span<const uint64_t> item, uint64_t &tag, size_t &idx) const
{
    uint64_t hash = hasher()(item);
    idx = idx_bucket_limit(hash);
    tag = tag_bit_limit(hash);
}

size_t CuckooFilter::get_alt_index(size_t idx, uint64_t tag) const
{
    uint64_t hash = hasher()(tag);
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

size_t CuckooFilter::save(ostream &out) const
{
    flatbuffers::FlatBufferBuilder fbs_builder(1024);

    // Get the raw table data of Cuckoo Filter Table and create the flatbuffer vector
    auto cuckoo_filter_table_data = fbs_builder.CreateVector(table_->get_raw_table_data());

    // Create the Cuckoo Filter Table flatbuffer object
    fbs::CuckooFilterTableBuilder cuckoo_filter_table_builder(fbs_builder);
    cuckoo_filter_table_builder.add_bits_per_tag(table_->get_bits_per_tag());
    cuckoo_filter_table_builder.add_num_buckets(table_->get_num_buckets());
    cuckoo_filter_table_builder.add_table(cuckoo_filter_table_data);
    auto cuckoo_filter_table = cuckoo_filter_table_builder.Finish();

    // Create the Cuckoo Filter Overflow Cache flatbuffer object
    fbs::CuckooFilterOverflowCacheBuilder cuckoo_filter_overflow_cache_builder(fbs_builder);
    cuckoo_filter_overflow_cache_builder.add_index(overflow_.index);
    cuckoo_filter_overflow_cache_builder.add_tag(overflow_.tag);
    cuckoo_filter_overflow_cache_builder.add_used(overflow_.used);
    auto cuckoo_filter_overflow_cache = cuckoo_filter_overflow_cache_builder.Finish();

    // Create the Cuckoo Filter flatbuffer object
    fbs::CuckooFilterBuilder cuckoo_filter_builder(fbs_builder);
    cuckoo_filter_builder.add_table(cuckoo_filter_table);
    cuckoo_filter_builder.add_num_items(num_items_);
    cuckoo_filter_builder.add_overflow(cuckoo_filter_overflow_cache);
    cuckoo_filter_builder.add_no_items_dropped(!dropped_items_);

    auto cuckoo_filter = cuckoo_filter_builder.Finish();
    fbs_builder.FinishSizePrefixed(cuckoo_filter);
    out.write(
        reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()), fbs_builder.GetSize());

    return fbs_builder.GetSize();
}

CuckooFilter CuckooFilter::Load(istream &in, size_t &bytes_read)
{
    vector<unsigned char> in_data(read_from_stream(in));

    auto verifier =
        flatbuffers::Verifier(reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
    bool safe = fbs::VerifySizePrefixedCuckooFilterBuffer(verifier);
    if (!safe) {
        throw runtime_error("failed to load parameters: invalid buffer");
    }

    const auto *cuckoo_filter_fbs = fbs::GetSizePrefixedCuckooFilter(in_data.data());
    const auto *cuckoo_filter_table_fbs = cuckoo_filter_fbs->table();
    const auto *cuckoo_filter_table_data_fbs = cuckoo_filter_table_fbs->table();

    vector<uint64_t> cuckoo_filter_table_data;
    cuckoo_filter_table_data.reserve(cuckoo_filter_table_data_fbs->size());
    copy(
        cuckoo_filter_table_data_fbs->cbegin(),
        cuckoo_filter_table_data_fbs->cend(),
        back_inserter(cuckoo_filter_table_data));

    // The constructors are what enforce the relationships between these fields, so that every
    // caller is held to them and not just this one. Report a violation the way this function
    // reports the rest of its input checks.
    auto make_filter = [&] {
        try {
            CuckooFilterTable cuckoo_filter_table(
                std::move(cuckoo_filter_table_data),
                cuckoo_filter_table_fbs->num_buckets(),
                cuckoo_filter_table_fbs->bits_per_tag());

            return CuckooFilter{ std::move(cuckoo_filter_table),
                                 static_cast<size_t>(cuckoo_filter_fbs->num_items()),
                                 static_cast<size_t>(cuckoo_filter_fbs->overflow()->index()),
                                 cuckoo_filter_fbs->overflow()->tag(),
                                 cuckoo_filter_fbs->overflow()->used(),
                                 !cuckoo_filter_fbs->no_items_dropped() };
        } catch (const invalid_argument &ex) {
            throw runtime_error(string("failed to load CuckooFilter: ") + ex.what());
        }
    };
    CuckooFilter cuckoo_filter = make_filter();

    bytes_read = in_data.size();
    return cuckoo_filter;
}
