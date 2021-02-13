// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD

// APSI
#include "cuckoo_filter.h"
#include "apsi/util/utils.h"

using namespace std;
using namespace apsi::sender::util;



template<typename ItemType, size_t bits_per_tag>
CuckooFilter<ItemType, bits_per_tag>::CuckooFilter(size_t key_count_max)
    : key_count_max_(key_count_max), victim_()
{
    size_t num_buckets = apsi::util::next_power_of_2(std::max<uint64_t>(1, key_count_max / CuckooFilterTable::tags_per_bucket_));

    victim_.used = false;
}

template <typename ItemType, size_t bits_per_tag>
bool CuckooFilter<ItemType, bits_per_tag>::is_present(const ItemType &item) const
{
    bool result = false;

    return result;
}

template <typename ItemType, size_t bits_per_tag>
void CuckooFilter<ItemType, bits_per_tag>::add(const ItemType &item)
{

}

template <typename ItemType, size_t bits_per_tag>
bool CuckooFilter<ItemType, bits_per_tag>::remove(const ItemType &item)
{

}
