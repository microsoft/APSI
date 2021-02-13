// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <vector>

// APSI
#include "cuckoo_filter_table.h"


namespace apsi {
    namespace sender {
        namespace util {

            template<typename ItemType, std::size_t bits_per_tag>
            class CuckooFilter {
            public:
                CuckooFilter(std::size_t key_count_max);

                bool is_present(const ItemType &item) const;
                void add(const ItemType &item);
                bool remove(const ItemType &item);

            private:
                std::size_t key_count_max_;

                struct VictimCache {
                    std::size_t index;
                    std::uint32_t tag;
                    bool used;
                };

                VictimCache victim_;
            };
        } // namespace util
    } // namespace sender
} // namespace apsi
