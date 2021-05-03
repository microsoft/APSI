// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

// GSL
#include "gsl/span"

// SEAL
#include "seal/modulus.h"

// APSI
#include "apsi/item.h"

namespace apsi {
    namespace util {
        // An element of a field with prime modulus < 2⁶⁴
        using felt_t = std::uint64_t;

        // A representation of item as a sequence felt_t
        using AlgItem = std::vector<felt_t>;

        // A representation of label as a sequence of felt_t
        using AlgLabel = std::vector<felt_t>;

        // A representation of item-label as a sequence of pairs of felt_t and std::vector<felt_t>
        using AlgItemLabel = std::vector<std::pair<felt_t, std::vector<felt_t>>>;

        /**
        Converts the given bitstring to a sequence of field elements (modulo `mod`).
        */
        std::vector<felt_t> bits_to_field_elts(
            BitstringView<const unsigned char> bits, const seal::Modulus &mod);

        /**
        Converts the given bitstring to a sequence of field elements (modulo `mod`).
        */
        std::vector<felt_t> bits_to_field_elts(
            BitstringView<unsigned char> bits, const seal::Modulus &mod);

        /**
        Converts the given field elements (modulo `mod`) to a bitstring.
        */
        Bitstring field_elts_to_bits(
            gsl::span<const felt_t> felts, std::uint32_t bit_count, const seal::Modulus &mod);

        /**
        Converts an item and label into a sequence of (felt_t, felt_t) pairs, where the the first
        pair value is a chunk of the item, and the second is a chunk of the label. item_bit_count
        denotes the bit length of the items and labels (they are the same length). mod denotes the
        modulus of the prime field.
        */
        AlgItemLabel algebraize_item_label(
            const HashedItem &item,
            const EncryptedLabel &label,
            std::size_t item_bit_count,
            const seal::Modulus &mod);

        /**
        Converts an item into a sequence of (felt_t, monostate) pairs, where the the first pair
        value is a chunk of the item, and the second is the unit type. item_bit_count denotes the
        bit length of the items and labels (they are the same length). mod denotes the modulus of
        the prime field. mod denotes the modulus of the prime field.
        */
        AlgItem algebraize_item(
            const HashedItem &item, std::size_t item_bit_count, const seal::Modulus &mod);

        /**
        Converts a sequence of field elements into a HashedItem. This will throw an invalid_argument
        if too many field elements are given, i.e., if modulus_bitlen * num_elements > 128.
        */
        HashedItem dealgebraize_item(
            const AlgItem &item, std::size_t item_bit_count, const seal::Modulus &mod);

        /**
        Converts a sequence of field elements into an EncryptedLabel. This will throw an
        invalid_argument if too many field elements are given, i.e., if modulus_bitlen *
        num_elements > 128.
        */
        EncryptedLabel dealgebraize_label(
            const AlgLabel &label, std::size_t label_bit_count, const seal::Modulus &mod);
    } // namespace util
} // namespace apsi
