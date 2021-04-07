// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <unordered_map>

namespace apsi {
    namespace receiver {
        class Receiver;

        class IndexTranslationTable {
            friend class Receiver;

        public:
            /**
            Translates a cuckoo table index to an index of the vector of items that were used to
            create this query. If the given table index was not populated, i.e., there is no
            translation, then this function returns the number of items encoded by this query.
            */
            std::size_t find_item_idx(std::size_t table_idx) const noexcept;

            /**
            Returns the number of items encoded by this index translation table.
            */
            std::size_t item_count() const noexcept
            {
                return item_count_;
            }

        private:
            IndexTranslationTable() = default;

            std::unordered_map<std::size_t, std::size_t> table_idx_to_item_idx_;

            std::size_t item_count_;
        };
    } // namespace receiver
} // namespace apsi
