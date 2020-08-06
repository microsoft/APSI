// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>
#include <utility>
#include <type_traits>
#include <cstring>
#include <algorithm>

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/plaintext.h"

// APSI
#include "apsi/item.h"

namespace apsi
{
    namespace util
    {
        // An element of a field with prime modulus < 2⁶⁴
        using felt_t = std::uint64_t;

        // A representation of item-label as a sequence of felt_t pairs, or item-unit as a sequence of pairs where the
        // first element is felt_t and the second is monostate
        template<typename L>
        using AlgItemLabel = std::vector<std::pair<felt_t, L> >;

        // Labels are always the same size as items
        using FullWidthLabel = Item;

        /**
        Converts the given bitstring to a sequence of field elements (modulo `mod`).
        */
        std::vector<felt_t> bits_to_field_elts(BitstringView<const seal::SEAL_BYTE> bits, const seal::Modulus &mod);

        /**
        Converts the given bitstring to a sequence of field elements (modulo `mod`).
        */
        std::vector<felt_t> bits_to_field_elts(BitstringView<seal::SEAL_BYTE> bits, const seal::Modulus &mod);

        /**
        Converts the given field elements (modulo `mod`) to a bitstring.
        */
        Bitstring field_elts_to_bits(gsl::span<const felt_t> felts, std::uint32_t bit_count, const seal::Modulus &mod);

        /**
        Converts an item and label into a sequence of (felt_t, felt_t) pairs, where the the first pair value is a chunk of
        the item, and the second is a chunk of the label. item_bit_count denotes the bit length of the items and labels
        (they are the same length). mod denotes the modulus of the prime field.
        */
        AlgItemLabel<felt_t> algebraize_item_label(
            const Item &item,
            const FullWidthLabel &label,
            std::size_t item_bit_count,
            const seal::Modulus &mod
        );

        /**
        Converts an item into a sequence of (felt_t, monostate) pairs, where the the first pair value is a chunk of the
        item, and the second is the unit type. item_bit_count denotes the bit length of the items and labels (they are the
        same length). mod denotes the modulus of the prime field. mod denotes the modulus of the prime field.
        */
        AlgItemLabel<monostate> algebraize_item(Item &item, std::size_t item_bit_count, const seal::Modulus &mod);
    }
} // namespace apsi
