// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

#include <cstddef>
#include <utility>
#include <cstring>
#include <stdexcept>
#include <random>
#include <wmmintrin.h>

namespace cuckoo
{
    #define CUCKOO_DEBUG

    using u64 = std::uint64_t;
    using u32 = std::uint32_t;
    using u16 = std::uint16_t;
    using u8 = std::uint8_t;
    using i64 = std::int64_t;
    using i32 = std::int32_t;
    using i16 = std::int16_t;
    using i8 = std::int8_t;

    // AES block
    using block = __m128i; 
    using item_type = block;
    
    enum class CuckooMode
    {
        Permutation = 0,
        Normal = 1
    };

    constexpr int bits_per_u64 = 64;

    constexpr int bytes_per_u64 = 8;

    constexpr int bits_per_block = 128;

    constexpr int bytes_per_block = 16;

    constexpr int bits_per_item = bits_per_block;

    constexpr int bytes_per_item = bytes_per_block;

    constexpr int max_log_table_size = 32;

    constexpr i64 max_table_size = 1LL << max_log_table_size;
    
    constexpr i64 max_loc_func_count = 16;

    constexpr int deBruijnTable64[64]{
        63,  0, 58,  1, 59, 47, 53,  2,
        60, 39, 48, 27, 54, 33, 42,  3,
        61, 51, 37, 40, 49, 18, 28, 20,
        55, 30, 34, 11, 43, 14, 22,  4,
        62, 57, 46, 52, 38, 26, 32, 41,
        50, 36, 17, 19, 29, 10, 13, 21,
        56, 45, 25, 31, 35, 16,  9, 12,
        44, 24, 15,  8, 23,  7,  6,  5
    };

    template<typename T>
    inline void set_block(const T *source, block *destination)
    {
#ifdef CUCKOO_DEBUG
        if(source == nullptr || destination == nullptr)
        {
            throw std::invalid_argument("source/destination cannot be null");
        }
#endif 
        std::memcpy(reinterpret_cast<std::byte*>(destination),
            reinterpret_cast<const std::byte*>(source), bytes_per_block);
    }

    inline void set_zero(block *destination)
    {
#ifdef CUCKOO_DEBUG
        if(destination == nullptr)
        {
            throw std::invalid_argument("destination cannot be null");
        }
#endif 
        std::memset(reinterpret_cast<std::byte*>(&destination), 0, 
            bytes_per_block);
    }

    inline u64 random_seed()
    {
        std::random_device rd;
        return (static_cast<u64>(rd()) << 32) + static_cast<u64>(rd());
    }

    inline void get_msb_index_generic(unsigned long *result, u64 value)
    {
#ifdef CUCKOO_DEBUG
        if(result == nullptr)
        {
            throw std::invalid_argument("result cannot be null");
        }
#endif
        value |= value >> 1;
        value |= value >> 2;
        value |= value >> 4;
        value |= value >> 8;
        value |= value >> 16;
        value |= value >> 32;

        *result = deBruijnTable64[
            ((value - (value >> 1)) * 0x07EDD5E59A4E28C2) >> 58];
    }

    inline int get_significant_bit_count(u64 value)
    {
        if (value == 0)
        {
            return 0;
        }

        unsigned long result;
        get_msb_index_generic(&result, value);
        return result + 1;
    }

    inline void set_block(u64 low_word, u64 high_word, block *destination)
    {
#ifdef CUCKOO_DEBUG
        if(destination == nullptr)
        {
            throw std::invalid_argument("destination cannot be null");
        }
#endif
        // Do it with memcpy to avoid strict aliasing problem
        // and hope that compiler won't actually call memcpy.
        std::memcpy(destination, &low_word, bytes_per_u64);
        std::memcpy(reinterpret_cast<std::byte*>(destination) + bytes_per_u64, 
            &high_word, bytes_per_u64);
    }

    inline block set_block(u64 low_word, u64 high_word)
    {
        block b;
        set_block(low_word, high_word, &b);
        return b;
    }

    inline block shift_right(block v, u64 n)
    {
        __m128i v1, v2;

        if (n >= 64)
        {
            v1 = _mm_srli_si128(v, 8);
            v1 = _mm_srli_epi64(v1, static_cast<int>(n - 64));
        }
        else
        {
            v1 = _mm_srli_epi64(v, static_cast<int>(n));
            v2 = _mm_srli_si128(v, 8);
            v2 = _mm_slli_epi64(v2, static_cast<int>(64 - n));
            v1 = _mm_or_si128(v1, v2);
        }
        return v1;
    }

    inline block shift_left(block v, u64 n)
    {
        __m128i v1, v2;

        if (n >= 64)
        {
            v1 = _mm_slli_si128(v, 8);
            v1 = _mm_slli_epi64(v1, static_cast<int>(n - 64));
        }
        else
        {
            v1 = _mm_slli_epi64(v, static_cast<int>(n));
            v2 = _mm_slli_si128(v, 8);
            v2 = _mm_srli_epi64(v2, static_cast<int>(64 - n));
            v1 = _mm_or_si128(v1, v2);
        }
        return v1;
    }
}
