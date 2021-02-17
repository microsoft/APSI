// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STL
#include <array>
#include <memory>
#include <vector>

// APSI
#include "cuckoo_filter_table.h"
#include "apsi/util/db_encoding.h"


namespace apsi {
    namespace sender {
        namespace util {

            class CuckooFilter {
            public:
                CuckooFilter(std::size_t key_count_max, std::size_t bits_per_tag);

                bool contains(const apsi::util::felt_t &item) const;
                bool add(const apsi::util::felt_t &item);
                bool remove(const apsi::util::felt_t &item);

            private:
                constexpr static std::size_t max_cuckoo_kicks_ = 500;

                std::size_t key_count_max_;
                std::size_t num_items_;

                struct OverflowCache {
                    std::size_t index;
                    std::uint32_t tag;
                    bool used;
                };

                OverflowCache overflow_;

                std::unique_ptr<CuckooFilterTable> table_;


                std::uint32_t tag_bit_limit(std::uint32_t value) const;
                std::size_t idx_bucket_limit(std::size_t value) const;
                void get_tag_and_index(const apsi::util::felt_t &item, std::uint32_t &tag, std::size_t &idx) const;
                std::size_t get_alt_index(std::size_t idx, std::uint32_t tag) const;
                bool add_index_tag(std::size_t idx, std::uint32_t tag);
                void try_eliminate_victim();
            };
        } // namespace util
    } // namespace sender
} // namespace apsi
