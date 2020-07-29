// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <type_traits>
#include <utility>
#include <stdexcept>
#include <algorithm>

// APSI
#include "apsi/util/stopwatch.h"

namespace apsi
{
    namespace util
    {
        /**
        Truncates a 64-bit value to a given number of (low-order) bits.
        */
        std::uint64_t truncate(std::uint64_t value, int bit_count)
        {
#ifdef APSI_DEBUG
            if (bit_count < 0 || bit_count > 64)
            {
                throw std::invalid_argument("bit_count is out of bounds");
            }
#endif
            if (bit_count == 0)
            {
                return 0;
            }
            else if (bit_count == 64)
            {
                return value;
            }

            return ((std::uint64_t(1) << bit_count) - 1) & value;
        }

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

        extern Stopwatch sender_stop_watch, recv_stop_watch;
    } // namespace util
} // namespace apsi
