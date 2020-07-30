// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <utility>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"
#include "seal/plaintext.h"

namespace apsi
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
    Identical to Bitstring, except the underlying data is not owned
    */
    class BitstringView
    {
    private:
        gsl::span<seal::SEAL_BYTE> data_;
        int bit_count_;

    public:
        BitstringView(gsl::span<seal::SEAL_BYTE> data, int bit_count)
        {
            // Sanity check: bit_count cannot be 0
            if (bit_count <= 0)
            {
                throw std::logic_error("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size() * 8 < static_cast<size_t>(bit_count))
            {
                throw std::logic_error("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (static_cast<size_t>(bit_count) <= (data.size()-1)*8)
            {
                throw std::logic_error("bit_count is at least a whole byte less than the underlying data length");
            }

            // Now move
            data_ = std::move(data);
            bit_count_ = bit_count;
        }

        inline bool operator==(const BitstringView &rhs)
        {
            // Check equivalence of pointers
            return (bit_count_ == rhs.bit_count_) && (data_.data() == rhs.data_.data());
        }

        int bit_count() const
        {
            return bit_count_;
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<seal::SEAL_BYTE> data()
        {
            return gsl::span(data_.data(), data_.size());
        }
    };

    /**
    Represents a bitstring, i.e., a string of bytes that tells you how many bits it's supposed to be interpreted as.
    The stated bit_count must be at most the number of actual underlying bits.
    */
    class Bitstring
    {
    private:
        std::vector<seal::SEAL_BYTE> data_;
        int bit_count_;

    public:
        Bitstring(std::vector<seal::SEAL_BYTE> &&data, int bit_count)
        {
            // Sanity check: bit_count cannot be 0
            if (bit_count <= 0)
            {
                throw std::logic_error("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size()*8 < static_cast<size_t>(bit_count))
            {
                throw std::logic_error("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (static_cast<size_t>(bit_count) <= (data.size()-1)*8)
            {
                throw std::logic_error("bit_count is at least a whole byte less than the underlying data length");
            }

            // Now move
            data_ = std::move(data);
            bit_count_ = bit_count;
        }

        inline bool operator==(const Bitstring &rhs)
        {
            return (bit_count_ == rhs.bit_count_) && (data_ == rhs.data_);
        }

        int bit_count()
        {
            return bit_count_;
        }

        /**
        Returns a BitstringView representing the same underlying data
        */
        BitstringView to_view()
        {
            return BitstringView(data(), bit_count_);
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<seal::SEAL_BYTE> data()
        {
            return gsl::span(data_.data(), data_.size());
        }
    };

    /**
    Converts the given bitstring to a sequence of field elements (modulo `mod`)
    */
    std::vector<felt_t> bits_to_field_elts(const Bitstring &bits, const seal::Modulus &mod);

    /**
    Converts the given field elements (modulo `mod`) to a bitstring
    */
    Bitstring field_elts_to_bits(const std::vector<felt_t> &felts, const seal::Modulus &mod);

    /**
    Converts an item and label into a sequence of (felt_t, felt_t) pairs, where the the first pair value is a chunk of
    the item, and the second is a chunk of the label. item_bit_count denotes the bit length of the items and labels
    (they're the same length). mod denotes the modulus of the prime field.
    */
    AlgItemLabel<felt_t> algebraize_item_label(Item &item, FullWidthLabel &label, size_t item_bit_count, Modulus& mod);

    /**
    Converts an item into a sequence of (felt_t, monostate) pairs, where the the first pair value is a chunk of the
    item, and the second is the unit type. item_bit_count denotes the bit length of the items and labels (they're the
    same length). mod denotes the modulus of the prime field. mod denotes the modulus of the prime field.
    */
    AlgItemLabel<monostate> algebraize_item(Item &item, size_t item_bit_count, Modulus &mod);
} // namespace apsi
