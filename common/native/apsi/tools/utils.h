// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <seal/context.h>
#include <seal/plaintext.h>
#include <string>
#include <type_traits>
#include "apsi/tools/stopwatch.h"

namespace apsi
{
    namespace tools
    {
        /**
        Find optimal split
        */
        u64 optimal_split(const u64 x, const int base);

        /**
        Given the supported degree and bound on powers, find the maximal represented power.
        i.e., we are given y^((b**i)*j) for i = 1,2,..., bound and j = 1,2,...,b-1.
        */
        u64 maximal_power(const u64 degree, const u64 bound, const u64 base);

        /**
        Convert the given input to digits
        */
        std::vector<u64> conversion_to_digits(const u64 input, const int base);

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
        u64 compute_sender_bin_size(
            u32 log_table_size, u64 sender_set_size, u32 hash_func_count, u32 binning_sec_level, u32 split_count);

        extern Stopwatch sender_stop_watch, recv_stop_watch;
    } // namespace tools
} // namespace apsi
