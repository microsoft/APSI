// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <type_traits>
#include <utility>
#include "apsi/util/stopwatch.h"

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
        auto partition_evenly(std::size_t count, std::size_t partition_count)
            -> std::vector<std::pair<std::size_t, std::size_t>>;

        extern Stopwatch sender_stop_watch, recv_stop_watch;
    } // namespace util
} // namespace apsi
