// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>

// APSI
#include "apsi/util/cuckoo_filter_table.h"

// GSL
#include "gsl/span"

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

                CuckooFilter(CuckooFilterTable& table, std::size_t table_num_items, std::size_t overflow_index, std::uint32_t overflow_tag, bool overflow_used);

                /**
                Indicates whether the given item is contained in the filter
                */
                bool contains(gsl::span<const std::uint64_t> item) const;

                /**
                Indicates whether the given item is contained in the filter
                */
                inline bool contains(std::uint64_t item) const
                {
                    std::array<std::uint64_t, 1> item_array{ item };
                    return contains(item_array);
                }

                /**
                Add an item to the Cuckoo Filter. Will fail if there is no more space to store
                items.
                */
                bool add(gsl::span<const std::uint64_t> item);

                /**
                Add an item to the Cuckoo Filter. Will fail if there is no more space to store
                items.
                */
                inline bool add(std::uint64_t item) {
                    return add({ &item, 1 });
                }

                /**
                Remove an item from the Cuckoo Filter.
                */
                bool remove(gsl::span<const std::uint64_t> item);

                /**
                Remove an item from the Cuckoo Filter.
                */
                bool remove(std::uint64_t item) {
                    return remove({ &item, 1 });
                }

                /**
                Get the number of items currently contained in the Cuckoo Filter
                */
                std::size_t get_num_items() const
                {
                    return num_items_;
                }

                /**
                Saves the CuckooFilter to a stream.
                */
                std::size_t save(std::ostream &out) const;

                /**
                Loads the CuckooFilter from a stream.
                */
                static CuckooFilter Load(std::istream& in, size_t& bytes_read);

            private:
                /**
                Maximum number of kicks before we give up trying to insert
                */
                constexpr static std::size_t max_cuckoo_kicks_ = 1000;

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
                    gsl::span<const std::uint64_t> item, std::uint32_t &tag, std::size_t &idx) const;

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
