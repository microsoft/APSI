// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// STD
#include <cstdint>
#include <utility> 

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
    typedef std::pair<u64, u64> seed128; 


    extern const block zero_block;
    extern const block one_block;
    extern const block all_one_block;
    extern const block cc_block;
}
