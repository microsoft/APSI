// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <cstdint>
#include <kuku/common.h>
#include "apsi/ffield/ffield_elt.h"

namespace apsi
{
    //TODO: Put these typedefs in a more appropriate location

    // An element of a field with prime modulus < 2⁶⁴
    using felt_t = std::uint64_t;

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
        Item(uint64_t *pointer);

        /**
        Constructs an item by hashing the string and using 'item_bit_count_' bits of the hash.
        */
        Item(const std::string &str);

        /**
        Constructs a short item (without hashing) by using 'item_bit_count_' bits of the specified uint64_t value.
        */
        Item(uint64_t item);

        Item(const kuku::item_type &item);

        /**
        Convert this item into an ffield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        FFieldElt to_ffield_element(FField ffield, size_t bit_length);

        /**
        Convert this item into the specified ffield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        void to_ffield_element(FFieldElt &ring_item, size_t bit_length);

        /**
        Returns the BitstringView representing this Item's data
        */
        BitstringView to_bitstring();

        Item &operator=(const Item &assign) = default;

        Item &operator=(const std::string &assign);

        Item &operator=(uint64_t assign);

        Item &operator=(const kuku::item_type &assign);

        bool operator==(const Item &other) const
        {
            return value_ == other.value_;
        }

        uint64_t &operator[](size_t i)
        {
            return value_[i];
        }

        const uint64_t &operator[](std::size_t i) const
        {
            return value_[i];
        }

        uint64_t *data()
        {
            return value_.data();
        }

        const uint64_t *data() const
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
        std::array<uint64_t, 2> value_;

    public:
        static constexpr std::size_t item_byte_count = sizeof(value_);
    }; // class Item
} // namespace apsi
