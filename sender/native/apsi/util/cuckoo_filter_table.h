// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <vector>


namespace apsi {
    namespace sender {
        namespace util {

            class CuckooFilterTable {
            public:
                CuckooFilterTable(std::size_t num_items, std::size_t bits_per_tag);

                std::uint32_t read_tag(std::size_t bucket, std::size_t tag_idx) const;
                void write_tag(std::size_t bucket, std::size_t tag_idx, std::uint32_t tag);

                std::size_t get_num_buckets() const
                {
                    return num_buckets_;
                }

                bool find_tag_in_bucket(std::size_t bucket, std::uint32_t tag) const;
                bool find_tag_in_buckets(
                    std::size_t bucket1, std::size_t bucket2, std::uint32_t tag) const;

            private:
                constexpr static std::size_t tags_per_bucket_ = 4;

                std::uint32_t tag_input_mask_;
                std::size_t bits_per_tag_;
                std::vector<std::uint64_t> table_;
                std::size_t num_buckets_;
            };

        } // namespace util
    } // namespace sender
} // namespace apsi
