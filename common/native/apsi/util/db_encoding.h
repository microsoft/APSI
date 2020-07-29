// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <utility>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>
#include <type_traits>

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"
#include "seal/plaintext.h"

namespace apsi
{
    // An element of a field with prime modulus < 2⁶⁴
    using felt_t = std::uint64_t;

    /**
    Identical to Bitstring, except the underlying data is not owned
    */
    template<typename T, typename = std::enable_if_t<std::is_same<seal::SEAL_BYTE, std::remove_cv_t<T>>::value>>
    class BitstringView
    {
    private:
        gsl::span<T> data_;

        std::uint32_t bit_count_;

    public:
        BitstringView(gsl::span<T> data, std::uint32_t bit_count)
        {
            // Sanity check: bit_count cannot be 0
            if (!bit_count)
            {
                throw std::logic_error("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size() * 8 < bit_count)
            {
                throw std::logic_error("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (bit_count <= (data.size()-1)*8)
            {
                throw std::logic_error("bit_count is at least a whole byte less than the underlying data length");
            }

            // Now move
            data_ = std::move(data);
            bit_count_ = bit_count;
        }

        inline bool operator==(const BitstringView<T> &rhs)
        {
            // Check equivalence of pointers
            return (bit_count_ == rhs.bit_count_) && (data_.data() == rhs.data_.data());
        }

        std::uint32_t bit_count() const
        {
            return bit_count_;
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<T> data() const
        {
            return { data_.data(), data_.size() };
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
        std::uint32_t bit_count_;

    public:
        Bitstring(std::vector<seal::SEAL_BYTE> &&data, std::uint32_t bit_count)
        {
            // Sanity check: bit_count cannot be 0
            if (!bit_count)
            {
                throw std::logic_error("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size()*8 < bit_count)
            {
                throw std::logic_error("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use
            // a smaller vector
            if (bit_count <= (data.size()-1)*8)
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

        std::uint32_t bit_count() const
        {
            return bit_count_;
        }

        /**
        Returns a BitstringView representing the same underlying data
        */
        BitstringView<seal::SEAL_BYTE> to_view()
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a BitstringView representing the same underlying data
        */
        BitstringView<const seal::SEAL_BYTE> to_view() const
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<seal::SEAL_BYTE> data()
        {
            return { data_.data(), data_.size() };
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<const seal::SEAL_BYTE> data() const
        {
            return { data_.data(), data_.size() };
        }
    };

    /**
    Converts the given bitstring to a sequence of field elements (modulo `mod`)
    */
    std::vector<felt_t> bits_to_field_elts(const BitstringView<const seal::SEAL_BYTE> &bits, const seal::Modulus &mod);

    /**
    Converts the given field elements (modulo `mod`) to a bitstring
    */
    Bitstring field_elts_to_bits(const std::vector<felt_t> &felts, const seal::Modulus &mod);

} // namespace apsi
