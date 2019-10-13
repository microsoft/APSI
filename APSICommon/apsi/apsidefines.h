// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <utility> 

// Kuku
#include <kuku/kuku.h>

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
    using block = __m128i;

    using u64 = std::uint64_t;
    using i64 = std::int64_t;
    using u32 = std::uint32_t;
    using i32 = std::int32_t;
    using u8 = std::uint8_t;
    using i8 = std::int8_t;

    extern const block zero_block;
    extern const block one_block;
    extern const block all_one_block;
    extern const block cc_block;

    using item_type = kuku::item_type;
    extern const item_type zero_item;
    extern const item_type one_item;
    extern const item_type all_one_item;
}
