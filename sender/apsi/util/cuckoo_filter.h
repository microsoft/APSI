// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

// APSI
#include "apsi/util/cuckoo_filter_table.h"

// GSL
#include "gsl/span"

namespace apsi::sender::util {
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
        [[nodiscard]] bool contains(gsl::span<const std::uint64_t> item) const;

        /**
        Indicates whether the given item is contained in the filter
        */
        [[nodiscard]] bool contains(std::uint64_t item) const
        {
            std::array<std::uint64_t, 1> item_array{ item };
            return contains(item_array);
        }

        /**
        Adds an item to the Cuckoo Filter, returning false if there is no space left for it. A
        filter is probabilistic and can refuse an item while holding fewer than its nominal
        capacity, when enough of them share a fingerprint. A refused item is not recorded
        anywhere, so the filter reports it absent; has_dropped_items then returns true and a
        caller must stop treating this filter's negative answers as authoritative.
        */
        [[nodiscard]] bool add(gsl::span<const std::uint64_t> item);

        /**
        Adds an item to the Cuckoo Filter, returning false if there is no space left for it. See
        the span overload for what a dropped item means.
        */
        [[nodiscard]] bool add(std::uint64_t item)
        {
            return add({ &item, 1 });
        }

        /**
        Returns whether this filter has ever refused an item. A filter that has refused one no
        longer knows everything it was asked to hold, so its negative answers stop being
        conclusive; contains may report an item absent that the caller went on to store
        elsewhere.
        */
        [[nodiscard]] bool has_dropped_items() const noexcept
        {
            return dropped_items_;
        }

        /**
        Removes an item from the Cuckoo Filter, returning false if no tag for it was found.

        Only call this for an item known to be in the set this filter describes. A filter stores
        fingerprints rather than items, so removing one that was never added can delete the last
        fingerprint belonging to a different item that happens to share it, after which the filter
        reports that other item absent though it is still there. Removing only items that were
        added keeps the count of each fingerprint exact and cannot lose one.
        */
        [[nodiscard]] bool remove(gsl::span<const std::uint64_t> item);

        /**
        Removes an item from the Cuckoo Filter, returning false if no tag for it was found. See
        the span overload for the precondition this carries.
        */
        [[nodiscard]] bool remove(std::uint64_t item)
        {
            return remove({ &item, 1 });
        }

        /**
        Get the number of items currently contained in the Cuckoo Filter
        */
        [[nodiscard]] std::size_t get_num_items() const
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
        static CuckooFilter Load(std::istream &in, std::size_t &bytes_read);

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
            std::uint64_t tag;
            bool used;
        };

        /**
        Last element that we were not able to insert in the table
        */
        OverflowCache overflow_{};

        /**
        Table that holds element tags
        */
        std::unique_ptr<CuckooFilterTable> table_;

        /**
        Create a new CuckooFilter from loaded data
        */
        CuckooFilter(
            CuckooFilterTable table,
            std::size_t table_num_items,
            std::size_t overflow_index,
            std::uint64_t overflow_tag,
            bool overflow_used,
            bool dropped_items);

        /**
        Returns a tag (limited by number of bits per tag)
        */
        [[nodiscard]] std::uint64_t tag_bit_limit(std::uint64_t value) const;

        /**
        Returns a bucket index (limited by number of buckets)
        */
        [[nodiscard]] std::size_t idx_bucket_limit(std::size_t value) const;

        /**
        Get the tag and bucket index for a given element
        */
        void get_tag_and_index(
            gsl::span<const std::uint64_t> item, std::uint64_t &tag, std::size_t &idx) const;

        /**
        Get the alternate index for a given tag/index combination
        */
        [[nodiscard]] std::size_t get_alt_index(std::size_t idx, std::uint64_t tag) const;

        /**
        Add the given tag/index combination to the table
        */
        bool add_index_tag(std::size_t idx, std::uint64_t tag);

        /**
        Whether an item has ever been refused. Once set it is never cleared: a later removal does
        not recover the identity of whatever was dropped.
        */
        bool dropped_items_ = false;

        /**
        Try to eliminate the current overflow item
        */
        void try_eliminate_overflow();
    };
} // namespace apsi::sender::util
