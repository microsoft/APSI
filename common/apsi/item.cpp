// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>

// APSI
#include "apsi/item.h"
#include "apsi/util/utils.h"

// GSL
#include "gsl/span"

using namespace std;

namespace apsi {
    void Item::hash_to_value(const void *in, size_t size)
    {
        APSI_blake2b(value_.data(), sizeof(value_), in, size, nullptr, 0);
    }

    Bitstring Item::to_bitstring(uint32_t item_bit_count) const
    {
        vector<unsigned char> bytes;
        bytes.reserve(sizeof(value_type));
        copy(value_.cbegin(), value_.cend(), back_inserter(bytes));
        return { std::move(bytes), item_bit_count };
    }

    string Item::to_string() const
    {
        // Render the 16-byte item as four uint32_t halves in the canonical [a, b, c, d] format
        // util::to_string produces.
        array<uint32_t, sizeof(value_) / sizeof(uint32_t)> halves{};
        static_assert(sizeof(halves) == sizeof(value_), "Item size mismatch");
        memcpy(halves.data(), value_.data(), sizeof(value_));
        return util::to_string(gsl::span<const uint32_t, halves.size()>(halves));
    }
} // namespace apsi
