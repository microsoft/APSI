// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <utility> 

// Cuckoo
#include <cuckoo/cuckoo.h>

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

#include "seal/ciphertext.h"

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

    using item_type = cuckoo::item_type;
    extern const item_type zero_item;
    extern const item_type one_item;
    extern const item_type all_one_item;
}
