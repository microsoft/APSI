// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <utility>

// Kuku
#include <kuku/kuku.h>

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
    using item_type = kuku::item_type;
    extern const item_type zero_item;
    extern const item_type one_item;
    extern const item_type all_one_item;
} // namespace apsi
