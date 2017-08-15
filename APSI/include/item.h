#pragma once

#include <array>
#include <string>
#include "util/exring.h"
#include "Tools/hash.h"
#include <stdexcept>
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

		/**
		Constructs an item by hahsing the uint64_t array and using 'item_bit_length_' bits of the hash.
		*/
		Item(uint64_t *pointer, int uint64_count);

		/**
		Constructs an item by hashing the string and using 'item_bit_length_' bits of the hash.
		*/
		Item(const std::string &str);

		/**
		Constructs a short item (without hashing) by using 'item_bit_length_' bits of the specified uint64_t value.
		*/
		Item(uint64_t item);
		
		static void set_item_bit_length(size_t len)
		{
			if (len > 128)
				throw std::invalid_argument("invalid bit length for items.");
			item_bit_length_ = len;
		}

		static void set_reduced_bit_length(size_t len)
		{
			if (len > 128)
				throw std::invalid_argument("invalid bit length for items.");
			reduced_bit_length_ = len;
		}

		/**
		Reduce (inplace) this item into an item that is stored in the permutation based hashing table.
		*/
		void to_itemL(cuckoo::PermutationBasedCuckoo &cuckoo, int hash_func_index);

		/**
		Reduce this item into an item that is stored in the permutation based hashing table, and return the new item. This item is not changed.
		*/
		Item itemL(cuckoo::PermutationBasedCuckoo &cuckoo, int hash_func_index) const;

		/**
		Convert this item into an exring element. Assuming that this item has been reduced in a hash table,
		we will only use 'reduced_bit_length_' bits of this item.
		*/
		seal::util::ExRingElement to_exring_element(std::shared_ptr<seal::util::ExRing> exring);

		/**
		Convert this item into the specified exring element. Assuming that this item has been reduced in a hash table,
		we will only use 'reduced_bit_length_' bits of this item.
		*/
		void to_exring_element(seal::util::ExRingElement &ring_item);

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

		bool operator ==(const Item &other) const
		{
			return value_ == other.value_;
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

		size_t uint64_count() const
		{
			return value_.size();
		}

		inline void fill(uint64_t value)
		{
			value_.fill(value);
		}

		size_t bit_count() const
		{
			return value_.size() * 64;
		}

	private:
		std::array<uint64_t, 2> value_;

		static const seal::util::HashFunction hf_;

		/* The bit length of an item, before being stored in a hash table. */
		static size_t item_bit_length_;

		/* This indicates the stored bit length in the hashing table (cuckoo or simple). 
		For example, the itemL_bit_length_ in the PermutationBasedCuckoo. */
		static size_t reduced_bit_length_;  
	};
}