// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/context.h>
#include <seal/plaintext.h>
#include <string>
#include <type_traits>
#include "apsi/util/stopwatch.h"

namespace apsi
{
    namespace util
    {
        /**
        Find optimal split
        */
        std::uint64_t optimal_split(const std::uint64_t x, const std::uint64_t base);

        /**
        Given the supported degree and bound on powers, find the maximal represented power.
        i.e., we are given y^((b**i)*j) for i = 1,2,..., bound and j = 1,2,...,b-1.
        */
        std::uint64_t maximal_power(const std::uint64_t degree, const std::uint64_t bound, const std::uint64_t base);

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
        Compute secure Sender bin size
        */
        std::uint64_t compute_sender_bin_size(
            std::uint32_t log_table_size, std::uint64_t sender_set_size, std::uint32_t hash_func_count, std::uint32_t binning_sec_level, std::uint32_t split_count);

        extern Stopwatch sender_stop_watch, recv_stop_watch;
    } // namespace util
} // namespace apsi
