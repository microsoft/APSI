// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <vector>

namespace apsi {
    namespace sender {
        namespace util {
            /**
            Implementation of a Cuckoo Filter table.
            Logically the table is divided in buckets. Each bucket is capable of storing up to
            tags_per_bucket_ tags. Each tags uses bits_per_tag_ bits of storage.
            */
            class CuckooFilterTable {
            public:
                /**
                Build an instance of a Cuckoo Filter Table
                */
                CuckooFilterTable(std::size_t num_items, std::size_t bits_per_tag);

                /**
                Read the tag at the given bucket and tag index within the bucket
                */
                std::uint32_t read_tag(std::size_t bucket, std::size_t tag_idx) const;

                /**
                Write a tag at the given bucket and tag index within the bucket
                */
                void write_tag(std::size_t bucket, std::size_t tag_idx, std::uint32_t tag);

                /**
                Insert a tag in the given bucket
                */
                bool insert_tag(
                    std::size_t bucket, std::uint32_t tag, bool kickout, std::uint32_t &old_tag);

                /**
                Delete a tag fromthe given bucket
                */
                bool delete_tag(std::size_t bucket, std::uint32_t tag);

                /**
                Get the number of buckets
                */
                std::size_t get_num_buckets() const
                {
                    return num_buckets_;
                }

                /**
                Get the number of bits to use per tag
                */
                std::size_t get_bits_per_tag() const
                {
                    return bits_per_tag_;
                }

                /**
                Find a tag in the given bucket
                */
                bool find_tag_in_bucket(std::size_t bucket, std::uint32_t tag) const;

                /**
                Find a tag in the given buckets
                */
                bool find_tag_in_buckets(
                    std::size_t bucket1, std::size_t bucket2, std::uint32_t tag) const;

            private:
                /**
                Indicates how many tags each bucket will contain
                */
                constexpr static std::size_t tags_per_bucket_ = 4;

                /**
                Number of bits per tag
                */
                std::size_t bits_per_tag_;

                /**
                Input elements will be limited with this mask
                */
                std::uint32_t tag_input_mask_;

                /**
                The bucket table is encoded as an array of uint64_t
                */
                std::vector<std::uint64_t> table_;

                /**
                Number of buckets in the current table
                */
                std::size_t num_buckets_;
            };
        } // namespace util
    }     // namespace sender
} // namespace apsi
