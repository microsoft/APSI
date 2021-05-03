// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <memory>
#include <vector>

// APSI
#include "apsi/util/cuckoo_filter_table.h"
#include "apsi/util/db_encoding.h"

namespace apsi {
    namespace sender {
        namespace util {

            /**
            Implementation of a Cuckoo Filter
            */
            class CuckooFilter {
            public:
                /**
                Build an instance of a Cuckoo Filter
                */
                CuckooFilter(std::size_t key_count_max, std::size_t bits_per_tag);

                /**
                Indicates whether the given item is contained in the filter
                */
                bool contains(const apsi::util::felt_t &item) const;

                /**
                Add an item to the Cuckoo Filter. Will fail if there is no more space to store
                items.
                */
                bool add(const apsi::util::felt_t &item);

                /**
                Remove an item from the Cuckoo Filter.
                */
                bool remove(const apsi::util::felt_t &item);

                /**
                Get the number of items currently contained in the Cuckoo Filter
                */
                std::size_t get_num_items() const
                {
                    return num_items_;
                }

            private:
                /**
                Maximum number of kicks before we give up trying to insert
                */
                constexpr static std::size_t max_cuckoo_kicks_ = 500;

                /**
                Number of items contained in the filter
                */
                std::size_t num_items_;

                /**
                Represents an element that we were not able to insert in the table
                */
                struct OverflowCache {
                    std::size_t index;
                    std::uint32_t tag;
                    bool used;
                };

                /**
                Last element that we were not able to insert in the table
                */
                OverflowCache overflow_;

                /**
                Table that holds element tags
                */
                std::unique_ptr<CuckooFilterTable> table_;

                /**
                Returns a tag (limited by number of bits per tag)
                */
                std::uint32_t tag_bit_limit(std::uint32_t value) const;

                /**
                Returns a bucket index (limited by number of buckets)
                */
                std::size_t idx_bucket_limit(std::size_t value) const;

                /**
                Get the tag and bucket index for a given element
                */
                void get_tag_and_index(
                    const apsi::util::felt_t &item, std::uint32_t &tag, std::size_t &idx) const;

                /**
                Get the alternate index for a given tag/index combination
                */
                std::size_t get_alt_index(std::size_t idx, std::uint32_t tag) const;

                /**
                Add the given tag/index combination to the table
                */
                bool add_index_tag(std::size_t idx, std::uint32_t tag);

                /**
                Try to eliminate the current overflow item
                */
                void try_eliminate_overflow();
            };
        } // namespace util
    }     // namespace sender
} // namespace apsi
