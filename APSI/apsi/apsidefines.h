#pragma once

// STD
#include <wmmintrin.h>
#include <utility>
#include <cstdint>
#include <vector>
#include <memory>
#include <string>

// APSI
#include "tools/stopwatch.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/context.h"

namespace apsi
{
    typedef __m128i block;

    typedef std::uint64_t u64;
    typedef std::int64_t i64;
    typedef std::uint32_t u32;
    typedef std::int32_t i32;
    typedef std::uint8_t u8;
    typedef std::int8_t i8;

    inline void zero_uint(u64 *destination, u64 u64_count)
    {
        std::memset(reinterpret_cast<unsigned char*>(destination), 0, 8 * u64_count);
    }

    std::uint64_t optimal_split(std::uint64_t x, int base);

    std::vector<std::uint64_t> conversion_to_digits(std::uint64_t input, int base);

    void split(const std::string &s, char delim, std::vector<std::string> &elems);

    std::vector<std::string> split(const std::string &s, char delim);

    seal::Plaintext random_plaintext(const seal::SEALContext &context);

    extern apsi::tools::Stopwatch stop_watch;
}
