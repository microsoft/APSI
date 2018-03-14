#pragma once

#include <array>
#include <string>
#include <stdexcept>
#include "seal/util/exfield.h"
#include "cuckoo.h"

namespace apsi
{
    class Item
    {
    public:
        /**
        Constructs a zero item.
        */
        Item()
        {
        }

        Item(const Item&) = default;

        /**
        Constructs an item by hahsing the uint64_t array and using 'item_bit_length_' bits of the hash.
        */
        Item(uint64_t *pointer);

        /**
        Constructs an item by hashing the string and using 'item_bit_length_' bits of the hash.
        */
        Item(const std::string &str);

        /**
        Constructs a short item (without hashing) by using 'item_bit_length_' bits of the specified uint64_t value.
        */
        Item(uint64_t item);


        Item(const cuckoo::block& item);
        


        /**
        Convert this item into an exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        seal::util::ExFieldElement to_exfield_element(std::shared_ptr<seal::util::ExField> &exfield, int bit_length);

        /**
        Convert this item into the specified exfield element. Assuming that this item has been reduced in a hash table,
        we will only use 'reduced_bit_length_' bits of this item.
        */
        void to_exfield_element(seal::util::ExFieldElement &ring_item, int bit_length);

        /**
        Return value of the i-th part of this item. We split the item into small parts,
        each of which has bit length specified by split_length (not bigger than 64). If
        split_length is not a factor of 64, the highest split of the item will be prepended
        with zero bits to most significant positions to match split_length.

        @param[in] i The i-th part.
        @param[in] split_length Bit length of each part.
        */
        uint64_t item_part(uint32_t i, uint32_t split_length);

        Item& operator =(const std::string &assign);

        Item& operator =(uint64_t assign);

        Item& operator =(const Item &assign);

        Item& operator =(const cuckoo::block&assign);

        bool operator ==(const Item &other) const
        {
            return value_ == other.value_;
        }


        operator cuckoo::block&() const
        {
            return *(cuckoo::block*)value_.data();
        }

        uint64_t& operator[](size_t i)
        {
            return value_[i];
        }

        const uint64_t& operator[](size_t i) const
        {
            return value_[i];
        }

        uint64_t* data()
        {
            return value_.data();
        }

        const uint64_t* data() const
        {
            return value_.data();
        }

        void save(std::ostream &stream) const;

        void load(std::istream &stream);

    private:
        std::array<uint64_t, 2> value_;
    };
}