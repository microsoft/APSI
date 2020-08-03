// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

// Kuku
#include "kuku/common.h"

// GSL
#include "gsl/span"

// SEAL
#include "seal/util/defines.h"

// APSI
#include "apsi/util/db_encoding.h"

namespace apsi
{
    // The unit type
    struct monostate {};

    class Item
    {
    public:
        /**
        Constructs a zero item.
        */
        Item() : value_({ 0, 0 })
        {}

        Item(const Item &) = default;

        /**
        Constructs an item by hashing the uint64_t array and using 'item_bit_count_' bits of the hash.
        */
        Item(std::uint64_t *pointer);

        /**
        Constructs an item by hashing the string and using 'item_bit_count_' bits of the hash.
        */
        Item(const std::string &str);

        /**
        Constructs a short item (without hashing) by using 'item_bit_count_' bits of the specified uint64_t value.
        */
        Item(std::uint64_t item);

        Item(const kuku::item_type &item);

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

        Item &operator=(const Item &assign) = default;

        Item &operator=(const std::string &assign);

        Item &operator=(std::uint64_t assign);

        Item &operator=(const kuku::item_type &assign);

        bool operator==(const Item &other) const
        {
            return value_ == other.value_;
        }

        std::uint64_t &operator[](std::size_t i)
        {
            return value_[i];
        }

        const std::uint64_t &operator[](std::size_t i) const
        {
            return value_[i];
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

        /**
        Parse the current item from a string.

        The parser supports only base 10 and base 16 strings.
        When parsing a base 16 string, do _not_ include a preceding '0x'.
        */
        void parse(const std::string &input, std::uint32_t base);

        /**
        Parse the current item from a string.

        If the string starts with '0x', it will be considered hexadecimal.
        Otherwise it will be considered base 10.
        */
        void parse(const std::string &input);

    private:
        std::array<std::uint64_t, 2> value_;
    }; // class Item
} // namespace apsi
