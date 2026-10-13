// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <unordered_map>
#include <utility>
#include <vector>

namespace apsi::receiver {
    class Receiver;

    class IndexTranslationTable {
        friend class Receiver;

    public:
        /**
        Translates a cuckoo table index to an index of the vector of items that were used to
        create this query. If the given table index was not populated, i.e., there is no
        translation, then this function returns the number of items encoded by this query. An
        item that appears more than once in the vector is translated to its first index.
        */
        [[nodiscard]] std::size_t find_item_idx(std::size_t table_idx) const noexcept;

        /**
        Returns the number of items encoded by this index translation table.
        */
        [[nodiscard]] std::size_t item_count() const noexcept
        {
            return item_count_;
        }

    private:
        IndexTranslationTable() = default;

        std::unordered_map<std::size_t, std::size_t> table_idx_to_item_idx_;

        /**
        Pairs of indices into the vector of items: an index of an item that appears earlier in the
        vector as well, and the item's first index, whose MatchRecord is copied to it.
        */
        std::vector<std::pair<std::size_t, std::size_t>> repeated_items_;

        std::size_t item_count_{};
    };
} // namespace apsi::receiver
