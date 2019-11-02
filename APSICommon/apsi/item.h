// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <array>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <cstddef>

// APSI
#include "apsi/ffield/ffield_elt.h"

// Kuku
#include <kuku/common.h>

namespace apsi
{
    class Item
    {
    public:
        /**
        Constructs a zero item.
        */
        Item()
            : value_({ 0, 0 })
        {
        }

        Item(const Item&) = default;

        /**
        Constructs an item by hahsing the std::uint64_t array and using 'item_bit_count_' bits of the hash.
        */
        Item(std::uint64_t *pointer);

        /**
        Constructs an item by hashing the string and using 'item_bit_count_' bits of the hash.
        */
        Item(const std::string &str);

        /**
        Constructs a short item (without hashing) by using 'item_bit_count_' bits of the specified std::uint64_t value.
        */
        Item(std::uint64_t item);


        Item(const kuku::item_type& item);
        
        /**
        Convert this item into an exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        FFieldElt to_exfield_element(FField exfield, int bit_length);

        /**
        Convert this item into the specified exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        void to_exfield_element(FFieldElt &ring_item, int bit_length);

        Item& operator =(const std::string &assign);

        Item& operator =(std::uint64_t assign);

        Item& operator =(const Item &assign);

        Item& operator =(const kuku::item_type &assign);

        bool operator ==(const Item &other) const
        {
            return value_ == other.value_;
        }

        std::uint64_t& operator[](size_t i)
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

        void save(std::ostream &stream) const;

        void load(std::istream &stream);

        auto& get_value() { return value_; }

        const auto& get_value() const { return value_; }

        /**
        Parse the current item from a string.

        The parser supports only base 10 and base 16 strings.
        When parsing a base 16 string, do _not_ include a preceding '0x'.
        */
        void parse(const std::string& input, int base);

        /**
        Parse the current item from a string.

        If the string starts with '0x', it will be considered hexadecimal.
        Otherwise it will be considered base 10.
        */
        void parse(const std::string& input);

    private:
        std::array<std::uint64_t, 2> value_;

        std::uint32_t muladd(std::uint32_t item[4], int mul, int add);

    public:
        static constexpr std::size_t item_byte_count = sizeof(value_);
    };
}
