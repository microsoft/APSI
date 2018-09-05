#pragma once

// STD
#include <vector>

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
        inline void zero_uint(u64 *destination, u64 u64_count)
        {
            std::memset(reinterpret_cast<unsigned char*>(destination), 0, 8 * u64_count);
        }

        /**
        Find optimal split
        */
        std::uint64_t optimal_split(std::uint64_t x, int base);

        /**
        Convert the given input to digits
        */
        std::vector<std::uint64_t> conversion_to_digits(std::uint64_t input, int base);

        /**
        Split the given string
        */
        void split(const std::string &s, char delim, std::vector<std::string> &elems);

        /**
        Split the given string
        */
        std::vector<std::string> split(const std::string &s, char delim);

        /**
        Generate a random plaintext
        */
        seal::Plaintext random_plaintext(const seal::SEALContext &context);

        /**
        Round up the given value using the given step
        */
        inline u64 round_up_to(u64 val, u64 step) { return ((val + step - 1) / step) * step; }

        extern apsi::tools::Stopwatch stop_watch, recv_stop_watch;
    }
}
