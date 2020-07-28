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
#include <gsl/span>

// SEAL
#include <seal/plaintext.h>

namespace apsi
{
    // An element of a field with prime modulus < 2⁶⁴
    using felt_t = std::uint64_t;

    /**
    Identical to Bitstring, except the underlying data is not owned
    */
    class BitstringView
    {
    private:
        gsl::span<std::uint8_t> data_;
        std::size_t bit_len_;

    public:

        BitstringView(gsl::span<std::uint8_t> &&data, std::size_t bit_len)
        {
            // Sanity check: bitlen cannot be 0
            if (bit_len == 0)
            {
                throw std::logic_error("Given bitlen is 0");
            }
            // Sanity check: bitlen cannot exceed underlying data len
            if (data.size()*8 < bit_len)
            {
                throw std::logic_error("Given bitlen exceeds the data length!");
            }
            // Sanity check: bitlen should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (bit_len <= (data.size()-1)*8)
            {
                throw std::logic_error("Given bitlen is at least a whole byte less than the underlying data len");
            }

            // Now move
            data_ = std::move(data);
            bit_len_ = bit_len;
        }

        inline bool operator==(const BitstringView &rhs)
        {
            // Check equivalence of pointers
            return (bit_len_ == rhs.bit_len_) && (data_.data() == rhs.data_.data());
        }

        std::size_t bit_len()
        {
            return bit_len_;
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<std::uint8_t> data()
        {
            return gsl::span(data_.data(), data_.size());
        }
    };

    /**
    Represents a bitstring, i.e., a string of bytes that tells you how many bits it's supposed to be interpreted as.
    The stated bitlen must be at most the number of actual underlying bits.
    */
    class Bitstring
    {
    private:
        std::vector<std::uint8_t> data_;
        std::size_t bit_len_;

    public:

        Bitstring(std::vector<std::uint8_t> &&data, std::size_t bit_len)
        {
            // Sanity check: bitlen cannot be 0
            if (bit_len == 0)
            {
                throw std::logic_error("Given bitlen is 0");
            }
            // Sanity check: bitlen cannot exceed underlying data len
            if (data.size()*8 < bit_len)
            {
                throw std::logic_error("Given bitlen exceeds the data length!");
            }
            // Sanity check: bitlen should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (bit_len <= (data.size()-1)*8)
            {
                throw std::logic_error("Given bitlen is at least a whole byte less than the underlying data len");
            }

            // Now move
            data_ = std::move(data);
            bit_len_ = bit_len;
        }

        inline bool operator==(const Bitstring &rhs)
        {
            return (bit_len_ == rhs.bit_len_) && (data_ == rhs.data_);
        }

        std::size_t bit_len()
        {
            return bit_len_;
        }

        /**
        Returns a BitstringView representing the same underlying data
        */
        BitstringView to_view()
        {
            return BitstringView(data(), bit_len_);
        }

        /**
        Returns a reference to the underlying bytes
        */
        gsl::span<std::uint8_t> data()
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

} // namespace apsi
