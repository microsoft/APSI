#pragma once

// STD
#include <cstdint>

// Intrinsics
#include <wmmintrin.h>


#ifdef _MSC_VER
#ifdef _DEBUG
#undef NDEBUG
#else
#ifndef NDEBUG
#define NDEBUG
#endif
#endif
#endif

namespace apsi
{
    typedef __m128i block;

    typedef std::uint64_t u64;
    typedef std::int64_t i64;
    typedef std::uint32_t u32;
    typedef std::int32_t i32;
    typedef std::uint8_t u8;
    typedef std::int8_t i8;

    extern const block zero_block;
    extern const block one_block;
    extern const block all_one_block;
    extern const block cc_block;
}
