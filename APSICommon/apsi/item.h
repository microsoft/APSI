// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <string>
#include <stdexcept>
#include <cstddef>
#include <kuku/common.h>
#include "apsi/ffield/ffield_elt.h"

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
        Constructs an item by hahsing the u64 array and using 'item_bit_count_' bits of the hash.
        */
        Item(u64 *pointer);

        /**
        Constructs an item by hashing the string and using 'item_bit_count_' bits of the hash.
        */
        Item(const std::string &str);

        /**
        Constructs a short item (without hashing) by using 'item_bit_count_' bits of the specified u64 value.
        */
        Item(u64 item);


        Item(const kuku::item_type& item);
        
        /**
        Convert this item into an exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        FFieldElt to_ffield_element(FField exfield, int bit_length);

        /**
        Convert this item into the specified exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        void to_ffield_element(FFieldElt &ring_item, int bit_length);

        Item& operator =(const std::string &assign);

        Item& operator =(u64 assign);

        Item& operator =(const Item &assign);

        Item& operator =(const kuku::item_type &assign);

        bool operator ==(const Item &other) const
        {
            return value_ == other.value_;
        }

        u64& operator[](size_t i)
        {
            return value_[i];
        }

        const u64 &operator[](std::size_t i) const
        {
            return value_[i];
        }

        u64 *data()
        {
            return value_.data();
        }

        const u64 *data() const
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
        std::array<u64, 2> value_;

        u32 muladd(u32 item[4], int mul, int add);

    public:
        static constexpr std::size_t item_byte_count = sizeof(value_);
    }; // class Item
} // namespace apsi
