#pragma once

#include <wmmintrin.h>
#include <utility>
#include <cstdint>
#include <vector>
#include "Tools/stopwatch.h"
#include <memory>
#include "plaintext.h"
#include "rnscontext.h"

namespace apsi
{
    typedef __m128 block;

    typedef std::uint64_t u64;

    inline void zero_uint(u64 *destination, u64 u64_count)
    {
        std::memset(reinterpret_cast<unsigned char*>(destination), 0, 8 * u64_count);
    }

    void right_shift_uint(const u64 *source, u64 *destination, u64 shift_amount, u64 u64_count);

    void left_shift_uint(const u64 *source, u64 *destination, u64 shift_amount, u64 u64_count);

    uint64_t optimal_split(uint64_t x, int base);

    std::vector<uint64_t> conversion_to_digits(uint64_t input, int base);

    void split(const std::string &s, char delim, std::vector<std::string> &elems);

    std::vector<std::string> split(const std::string &s, char delim);

    seal::Plaintext random_plaintext(const seal::RNSContext &context);

    extern apsi::tools::Stopwatch stop_watch;

    class BadReceiveBufferSize : public std::exception
    {
    public:
        const char* mWhat;
        u64 mLength;
        std::unique_ptr<char[]> mData;

        BadReceiveBufferSize(const char* what, u64 length, std::unique_ptr<char[]>&& data)
            :
            mWhat(what),
            mLength(length),
            mData(std::move(data))
        { }
    };
}