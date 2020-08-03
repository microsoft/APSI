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
#include <cstring>
#include <algorithm>

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/plaintext.h"

namespace apsi
{
    // An element of a field with prime modulus < 2⁶⁴
    using felt_t = std::uint64_t;

    /**
    Identical to Bitstring, except the underlying data is not owned.
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
            if (bit_count <= (data.size() - 1) * 8)
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
        Returns a reference to the underlying bytes.
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
            if (data.size() * 8 < bit_count)
            {
                throw std::logic_error("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use
            // a smaller vector
            if (bit_count <= (data.size() - 1) * 8)
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
        Returns a BitstringView representing the same underlying data.
        */
        BitstringView<seal::SEAL_BYTE> to_view()
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a BitstringView representing the same underlying data.
        */
        BitstringView<const seal::SEAL_BYTE> to_view() const
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a reference to the underlying bytes.
        */
        gsl::span<seal::SEAL_BYTE> data()
        {
            return { data_.data(), data_.size() };
        }

        /**
        Returns a reference to the underlying bytes.
        */
        gsl::span<const seal::SEAL_BYTE> data() const
        {
            return { data_.data(), data_.size() };
        }

        /**
        Appends another Bitstring or BitstringView to this one.
        */
        template<typename T>
        void append(const BitstringView<T> &other)
        {
            if (!(bit_count_ & 0x7))
            {
                // Easy case where the current bit-count is a multiple of 8 so we can just append the bytes
                data_.resize(seal::util::add_safe(other.data().size(), data_.size()));
                std::memcpy(data_.data() + (bit_count_ >> 3), other.data().data(), other.data().size());
                bit_count_ += other.bit_count();
            }
            else
            {
                // This Bitstring is not at a byte boundary; we need to shift-copy the new data
                data_.resize(seal::util::add_safe(other.data().size(), data_.size()));

                std::uint32_t neg_shift_amount = bit_count_ & 0x7;
                std::uint32_t shift_amount = std::uint32_t(8) - neg_shift_amount;

                seal::SEAL_BYTE shift_reg{ 0 };
                seal::SEAL_BYTE shift_reg_mask = static_cast<seal::SEAL_BYTE>((1 << neg_shift_amount) - 1);

                std::transform(other.data().rbegin(), other.data().rend(), data_.rbegin(), [&](auto cur_byte) {
                    seal::SEAL_BYTE ret = (cur_byte >> shift_amount) | shift_reg;
                    shift_reg = (cur_byte & shift_reg_mask) << shift_amount;
                    return ret;
                });

                bit_count_ += other.bit_count();

                // We might have ended up in a situation where the data has an extra empty byte
                if (bit_count_ <= (data_.size() - 1) * 8)
                {
                    data_.resize(data_.size() - 1);
                }
            }
        }

        /**
        Appends another Bitstring or BitstringView to this one.
        */
        void append(const Bitstring &other)
        {
            append(other.to_view());
        }
    };

    /**
    Converts the given bitstring to a sequence of field elements (modulo `mod`).
    */
    std::vector<felt_t> bits_to_field_elts(const BitstringView<const seal::SEAL_BYTE> &bits, const seal::Modulus &mod);

    /**
    Converts the given field elements (modulo `mod`) to a bitstring.
    */
    Bitstring field_elts_to_bits(gsl::span<const felt_t> felts, const seal::Modulus &mod);

} // namespace apsi
