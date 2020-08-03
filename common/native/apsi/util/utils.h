// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <cstdint>
#include <vector>
#include <type_traits>
#include <utility>
#include <stdexcept>
#include <algorithm>
#include <iostream>

// APSI
#include "apsi/util/stopwatch.h"

// SEAL
#include "seal/util/defines.h"

namespace apsi
{
    namespace util
    {
        /**
        Convert the given input to digits
        */
        std::vector<std::uint64_t> conversion_to_digits(const std::uint64_t input, const std::uint64_t base);

        /**
        Split the given string
        */
        void split(const std::string &s, const char delim, std::vector<std::string> &elems);

        /**
        Split the given string
        */
        std::vector<std::string> split(const std::string &s, const char delim);

        /**
        Round up the given value using the given step
        */
        template <typename T>
        typename std::enable_if<std::is_pod<T>::value, T>::type round_up_to(const T val, const T step)
        {
            return ((val + step - 1) / step) * step;
        }

        /**
        Partitions count many points into partition_count many disjoint parts as equally as
        possible. If count or partition_count is zero, the result is empty. If partition_count
        if larger than count, only count many partitions will be returned, each of size 1.
        The return value is a vector of pairs of points, where each pair contains the start
        and one-past-end points for the partition.
        */
        template<typename T>
        std::vector<std::pair<T, T>> partition_evenly(T count, T partition_count)
        {
            if (count == 0 || partition_count == 0)
            {
                return {};
            }

            partition_count = std::min(count, partition_count);

            std::vector<std::pair<T, T>> partitions;
            partitions.reserve(min(count, partition_count) + 1);

            // May be zero
            T per_partition = count / partition_count;
            T extras_needed = count - per_partition * partition_count;

            T partition_start = 0;
            for (T i = 0; i < partition_count; i++)
            {
                T partition_end = partition_start + per_partition;
                if (extras_needed)
                {
                    partition_end++;
                    extras_needed--;
                }
                partitions.push_back({ partition_start, partition_end });
                partition_start = partition_end;
            }

            return partitions;
        }

        /**
        This function reads a given number of bytes from a stream in small parts, writing the result to the end of
        a given vector. This can avoid issues where a large number of bytes is requested incorrectly to be read from
        a stream, causing a larger than necessary memory allocation.
        */
        void read_from_stream(std::istream &in, std::uint32_t byte_count, std::vector<seal::SEAL_BYTE> &destination);

        /**
        This function reads a size-prefixed number of bytes from a stream and returns the result in a vector.
        */
        std::vector<seal::SEAL_BYTE> read_from_stream(std::istream &in);

        extern Stopwatch sender_stop_watch, recv_stop_watch;
    } // namespace util
} // namespace apsi
