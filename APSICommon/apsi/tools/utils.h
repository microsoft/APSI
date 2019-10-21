// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <type_traits>

// APSI
#include "stopwatch.h"
#include "apsi/apsidefines.h"

// SEAL
#include "seal/context.h"
#include "seal/plaintext.h"

namespace apsi
{
    namespace tools
    {
        /**
        Get a random block that can be securely used as a seed for a PRNG
        */
        block sys_random_seed();

        /**
        Returns whether the given blocks are not equal
        */
        bool not_equal(const apsi::block& lhs, const apsi::block& rhs);

        /**
        Fill a given number of 64 bit words with zeros
        */
        inline void zero_uint(apsi::u64 *destination, const std::size_t u64_count)
        {
            std::memset(reinterpret_cast<unsigned char*>(destination), 0, 8 * u64_count);
        }

        /**
        Find optimal split
        */
        apsi::u64 optimal_split(const apsi::u64 x, const int base);

        /**
        Given the supported degree and bound on powers, find the maximal represented power.	
        i.e., we are given y^((b**i)*j) for i = 1,2,..., bound and j = 1,2,...,b-1.
        */
        apsi::u64 maximal_power(const apsi::u64 degree, const apsi::u64 bound, const apsi::u64 base);

        /**
        Convert the given input to digits
        */
        std::vector<apsi::u64> conversion_to_digits(const apsi::u64 input, const int base);

        /**
        Split the given string
        */
        void split(const std::string &s, const char delim, std::vector<std::string> &elems);

        /**
        Split the given string
        */
        std::vector<std::string> split(const std::string &s, const char delim);

        /**
        Generate a random plaintext
        */
        seal::Plaintext random_plaintext(const seal::SEALContext &context);

        /**
        Round up the given value using the given step
        */
        template<typename T>
        typename std::enable_if<std::is_pod<T>::value, T>::type
        round_up_to(const T val, const T step) { return ((val + step - 1) / step) * step; }

        /**
        Compute secure Sender bin size
        */
        apsi::u64 compute_sender_bin_size(apsi::u32 log_table_size, apsi::u64 sender_set_size, apsi::u32 hash_func_count, apsi::u32 binning_sec_level, apsi::u32 split_count);

        extern apsi::tools::Stopwatch sender_stop_watch, recv_stop_watch;
    }
}
