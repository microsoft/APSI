// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>

// Kuku
#include "kuku/common.h"

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"
#include "seal/util/blake2.h"

namespace apsi
{
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
                throw std::invalid_argument("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size() * 8 < bit_count)
            {
                throw std::invalid_argument("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use a
            // smaller vector
            if (bit_count <= (data.size() - 1) * 8)
            {
                throw std::invalid_argument("bit_count is at least a whole byte less than the underlying data length");
            }

            // Now move
            data_ = std::move(data);
            bit_count_ = bit_count;
        }

        template<typename S>
        BitstringView(const BitstringView<S> &view)
        {
            data_ = static_cast<gsl::span<S>>(view.data());
            bit_count_ = view.bit_count();
        }

        inline bool operator==(const BitstringView<T> &rhs) const
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
                throw std::invalid_argument("bit_count must be positive");
            }
            // Sanity check: bit_count cannot exceed underlying data length
            if (data.size() * 8 < bit_count)
            {
                throw std::invalid_argument("bit_count exceeds the data length");
            }
            // Sanity check: bit_count should not be more than 7 bits from the total length. If you want that, use
            // a smaller vector
            if (bit_count <= (data.size() - 1) * 8)
            {
                throw std::invalid_argument("bit_count is at least a whole byte less than the underlying data length");
            }

            // Now move
            data_ = std::move(data);
            bit_count_ = bit_count;
        }

        inline bool operator==(const Bitstring &rhs) const
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
    };

    class Item
    {
    public:
        /**
        Constructs a zero item.
        */
        Item() : value_({ 0, 0 })
        {}

        Item(std::array<std::uint64_t, 2> value) : value_(std::move(value))
        {}

        Item(const Item &) = default;

        Item(Item &&) = default;

        Item &operator =(const Item &item) = default;

        Item &operator =(Item &&item) = default;

        template<typename CharT>
        Item(const std::basic_string<CharT> &str)
        {
            operator =<CharT>(str);
        }

        /**
        Hash a given string of arbitrary length into an Item.
        */
        template<typename CharT>
        Item &operator =(const std::basic_string<CharT> &str)
        {
            blake2b(value_.data(), sizeof(value_), str.data(), str.size() * sizeof(CharT), nullptr, 0);
            return *this;
        }

        /**
        Returns the BitstringView representing this Item's data
        */
        BitstringView<seal::SEAL_BYTE> to_bitstring(std::uint32_t item_bit_count)
        {
            gsl::span<seal::SEAL_BYTE> bytestring_view(reinterpret_cast<seal::SEAL_BYTE*>(data()), sizeof(Item));
            return { bytestring_view, item_bit_count };
        }

        /**
        Returns the BitstringView representing this Item's data
        */
        BitstringView<const seal::SEAL_BYTE> to_bitstring(std::uint32_t item_bit_count) const
        {
            gsl::span<const seal::SEAL_BYTE> bytestring_view(
                reinterpret_cast<const seal::SEAL_BYTE*>(data()), sizeof(Item));
            return { bytestring_view, item_bit_count };
        }

        bool operator==(const Item &other) const
        {
            return value_ == other.value_;
        }

        std::uint64_t &operator[](std::size_t word_index)
        {
            return value_[word_index];
        }

        std::uint64_t *data()
        {
            return value_.data();
        }

        const std::uint64_t *data() const
        {
            return value_.data();
        }

        auto &value()
        {
            return value_;
        }

        const auto &value() const
        {
            return value_;
        }

        std::string to_string(std::uint32_t item_bit_count = 8 * sizeof(Item)) const
        {
            auto bsv = to_bitstring(item_bit_count);
            std::stringstream ss;
            ss << "[ ";
            for (auto a : bsv.data())
            {
                ss << static_cast<uint32_t>(a) << " ";
            }
            ss << "]";
            return ss.str();
        }

    private:
        std::array<std::uint64_t, 2> value_;
    }; // class Item
} // namespace apsi
