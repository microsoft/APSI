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
    TODO: (Michael) These functions are only here because to_bitstring needs to know how to encode an item (which is
    just array<uint64_t, 2>) into a bitstring. This problem goes away if Items are redefined to be array<seal_byte, 16>.
    So the TODO is to redefine Item as such, and move these read/write helpers to an empty namespace in db_encoding.cpp
    where they originated.
    */

    /**
    Reads a sequence of 8 bytes as a little-endian encoded uint64_t
    */
    static uint64_t read_u64_little_endian(const std::array<seal::seal_byte, 8> &bytes)
    {
        uint64_t val = 0;
        val |= static_cast<uint64_t>(bytes[0]);
        val |= static_cast<uint64_t>(bytes[1]) << 8;
        val |= static_cast<uint64_t>(bytes[2]) << 16;
        val |= static_cast<uint64_t>(bytes[3]) << 24;
        val |= static_cast<uint64_t>(bytes[4]) << 32;
        val |= static_cast<uint64_t>(bytes[5]) << 40;
        val |= static_cast<uint64_t>(bytes[6]) << 48;
        val |= static_cast<uint64_t>(bytes[7]) << 56;

        return val;
    }

    /**
    Writes a uint64_t to a little-endian sequence of 8 bytes
    */
    static std::array<seal::seal_byte, 8> write_u64_little_endian(const uint64_t num)
    {
        std::array<seal::seal_byte, 8> bytes;

        bytes[0] = static_cast<seal::seal_byte>( num & 0x00000000000000FFULL);
        bytes[1] = static_cast<seal::seal_byte>((num & 0x000000000000FF00ULL) >> 8);
        bytes[2] = static_cast<seal::seal_byte>((num & 0x0000000000FF0000ULL) >> 16);
        bytes[3] = static_cast<seal::seal_byte>((num & 0x00000000FF000000ULL) >> 24);
        bytes[4] = static_cast<seal::seal_byte>((num & 0x000000FF00000000ULL) >> 32);
        bytes[5] = static_cast<seal::seal_byte>((num & 0x0000FF0000000000ULL) >> 40);
        bytes[6] = static_cast<seal::seal_byte>((num & 0x00FF000000000000ULL) >> 48);
        bytes[7] = static_cast<seal::seal_byte>((num & 0xFF00000000000000ULL) >> 56);

        return bytes;
    }

    /**
    Identical to Bitstring, except the underlying data is not owned.
    */
    template<typename T, typename = std::enable_if_t<std::is_same<seal::seal_byte, std::remove_cv_t<T>>::value>>
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
        std::vector<seal::seal_byte> data_;
        std::uint32_t bit_count_;

    public:
        Bitstring(std::vector<seal::seal_byte> &&data, std::uint32_t bit_count)
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
        BitstringView<seal::seal_byte> to_view()
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a BitstringView representing the same underlying data.
        */
        BitstringView<const seal::seal_byte> to_view() const
        {
            return { data(), bit_count_ };
        }

        /**
        Returns a reference to the underlying bytes.
        */
        gsl::span<seal::seal_byte> data()
        {
            return { data_.data(), data_.size() };
        }

        /**
        Returns a reference to the underlying bytes.
        */
        gsl::span<const seal::seal_byte> data() const
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

        Item(std::array<std::uint64_t, 2> value) : value_(value)
        {}

        Item(std::uint64_t lw, std::uint64_t hw) : Item(std::array<std::uint64_t, 2>{ lw, hw })
        {}

        /**
        Constructs an Item from a BitstringView. This throws an invalid_argument if the bitstring doesn't fit into an array<uint64_t, 2>.
        */
        template<typename T>
        Item(BitstringView<T> &bitstring)
        {
            gsl::span<seal::seal_byte> bitstring_bytes = bitstring.data();

            // Collect two 8-byte arrays of data. If there's more than that, throw an error
            auto bitstring_it = bitstring_bytes.begin();

            // Collect the first 8 bytes
            size_t i = 0;
            std::array<seal::seal_byte, 8> first_word_buf;
            for (; bitstring_it != bitstring_bytes.end(); bitstring_it++)
            {
                // Once we've copied 8 bytes, read it to a uint64_t
                if (i == 8)
                {
                    break;
                }

                first_word_buf[i] = *bitstring_it;
                i++;
            }
            uint64_t first_word = read_u64_little_endian(first_word_buf);

            // Collect the next 8 bytes
            i = 0;
            std::array<seal::seal_byte, 8> second_word_buf;
            for (; bitstring_it != bitstring_bytes.end(); bitstring_it++)
            {
                // Once we've copied 8 bytes, read it to a uint64_t
                if (i == 8)
                {
                    break;
                }

                second_word_buf[i] = *bitstring_it;
                i++;
            }
            uint64_t second_word = read_u64_little_endian(second_word_buf);

            // There should be no data left. If there is, that's an error.
            if (bitstring_it != bitstring_bytes.end())
            {
                throw std::invalid_argument("bitstring is too long to fit into an Item");
            }

            value_ = { first_word, second_word };
        }

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
            if (str.empty())
            {
                throw std::invalid_argument("str cannot be empty");
            }
            blake2b(value_.data(), sizeof(value_), str.data(), str.size() * sizeof(CharT), nullptr, 0);
            return *this;
        }

        /**
        Returns the Bitstring representing this Item's data, encoded in little-endian
        */
        Bitstring to_bitstring(std::uint32_t item_bit_count) const
        {
            // 2x uint64_t is 16x seal_byte
            std::vector<seal::seal_byte> bytes;
            bytes.reserve(16);

            for (uint64_t word : value_)
            {
                std::array<seal::seal_byte, 8> serialized_word = write_u64_little_endian(word);
                for (seal::seal_byte byte : serialized_word)
                {
                    bytes.push_back(byte);
                }
            }

            return Bitstring(std::move(bytes), item_bit_count);
        }

        bool operator==(const Item &other) const
        {
            return value_ == other.value_;
        }

        std::uint64_t &operator[](std::size_t word_index)
        {
            return value_[word_index];
        }

        const std::uint64_t &operator[](std::size_t word_index) const
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

    /**
    Represents an Item that has been hashed with an OPRF.
    */
    class HashedItem : public Item
    {
    public:
        using Item::Item;
    };
} // namespace apsi

namespace std
{
    /**
    Specializes the std::hash template for Item and HashedItem.
    */
    template <>
    struct hash<apsi::Item>
    {
        std::size_t operator()(const apsi::Item &item) const
        {
            std::uint64_t result = 17;
            result = 31 * result + item[0];
            result = 31 * result + item[1];
            return static_cast<std::size_t>(result);
        }
    };

    template <>
    struct hash<apsi::HashedItem>
    {
        std::size_t operator()(const apsi::HashedItem &item) const
        {
            return hash<apsi::Item>()(item);
        }
    };
} // namespace std

