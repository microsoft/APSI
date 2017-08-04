
#include "item.h"
#include <stdexcept>
#include "apsidefines.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsi
{
	const HashFunction Item::hf_({ 0, 0 });

	size_t Item::item_bit_length_(128);

	size_t Item::reduced_bit_length_(128);

	Item::Item(uint64_t *pointer, int uint64_count)
	{
		HashFunction::aes_block_type hash_block(HashFunction::zero_block);
		hf_(pointer, uint64_count, hash_block);

		value_[0] = hash_block.m128i_u64[0];
		value_[1] = hash_block.m128i_u64[1];

		if (item_bit_length_ < 64)
		{
			value_[0] &= (static_cast<uint64_t>(1) << item_bit_length_) - 1;
			value_[1] = 0;
		}
		else
		{
			value_[1] &= (static_cast<uint64_t>(1) << (item_bit_length_ - 64)) - 1;
		}
	}

	Item::Item(const string &str)
	{
		operator=(str);
	}

	Item::Item(uint64_t item)
	{
		operator=(item);
	}

	Item& Item::operator =(uint64_t assign)
	{
		if (item_bit_length_ > 64)
			throw logic_error("Cannot use this constructor for item_bit_length_ bigger than 64.");
		value_[0] = assign & (static_cast<uint64_t>(1) << item_bit_length_) - 1;
		value_[1] = 0;

		return *this;
	}

	Item& Item::operator =(const string &str)
	{
		int str_len = str.length(),
			complete_uint64_count = str_len / 8,
			remaining_byte_count = str_len % 8;
		const char *data = str.data();

		HashFunction::aes_block_type hash_block(HashFunction::zero_block);
		if (complete_uint64_count > 0)
			hf_(reinterpret_cast<const uint64_t*>(data), complete_uint64_count, hash_block);
		data += 8 * complete_uint64_count;
		uint64_t last = 0;
		for (int i = 0; i < remaining_byte_count; i++)
			last |= ((data[i] & 0xFFFF) << (i * 8));
		hf_(last, hash_block);

		value_[0] = hash_block.m128i_u64[0];
		value_[1] = hash_block.m128i_u64[1];

		if (item_bit_length_ < 64)
		{
			value_[0] &= (static_cast<uint64_t>(1) << item_bit_length_) - 1;
			value_[1] = 0;
		}
		else
		{
			value_[1] &= (static_cast<uint64_t>(1) << (item_bit_length_ - 64)) - 1;
		}

		return *this;
	}

	Item& Item::operator =(const Item &assign)
	{
		for (int i = 0; i < value_.size(); i++)
			value_[i] = assign.value_[i];
		return *this;
	}

	void Item::to_itemL(cuckoo::PermutationBasedCuckoo &cuckoo, int hash_func_index)
	{
		/* Step 1: Append location index to end of item */
		// First move to highest u64
		uint64_t *item_ptr = value_.data();
		item_ptr += cuckoo.bin_u64_length() - 1;

		// Clear null bit and location bits
		uint64_t top_u64_mask = (static_cast<uint64_t>(1) << (cuckoo.item_bit_length() % 64)) - 1;
		*item_ptr &= top_u64_mask;

		// Finally XOR in the location
		*item_ptr ^= (static_cast<uint64_t>(hash_func_index) << (cuckoo.item_bit_length() % 64));

		/* Step 2: Shift out the right part (logarithm of table size) of the item */
		right_shift_uint(value_.data(), value_.data(), cuckoo.log_capacity(), value_.size());
	}

	Item Item::itemL(cuckoo::PermutationBasedCuckoo &cuckoo, int hash_func_index)
	{
		Item item(*this);
		item.to_itemL(cuckoo, hash_func_index);
		return item;
	}

	ExRingElement Item::to_exring_element(std::shared_ptr<ExRing> exring)
	{
		ExRingElement ring_item(exring);
		to_exring_element(ring_item);
		return ring_item;
	}

	void Item::to_exring_element(ExRingElement &ring_item)
	{
		shared_ptr<ExRing> exring = ring_item.exring();
		int split_length = exring->coeff_modulus().significant_bit_count() - 1; // Should minus 1 to avoid wrapping around p^r
		int split_index_bound = reduced_bit_length_ / split_length; 
		int j = 0;
		for (; j < (exring->coeff_count() - 1) && j < split_index_bound; j++)
			ring_item[j].pointer()[0] = item_part(j, split_length);
		for (; j < (exring->coeff_count() - 1); j++)
			ring_item[j].pointer()[0] = 0;
	}

	uint64_t Item::item_part(uint32_t i, uint32_t split_length)
	{
		int i1 = (i * split_length) >> 6,
			i2 = ((i + 1) * split_length) >> 6,
			j1 = (i * split_length) & 0x3F,  // mod 64
			j2 = ((i + 1) * split_length) & 0x3F;  // mod 64
#ifdef _DEBUG
		if (split_length > 64 || i2 > value_.size() || (i2 == value_.size() && j2 > 0))
			throw invalid_argument("invalid split_length, or index out of range.");
#endif
		int mask = (1 << split_length) - 1;
		if (i1 == i2 || i2 == value_.size())
			return (value_[i1] >> j1) & mask;
		else
			return ((value_[i1] >> j1) & mask) | ((value_[i2] << (64 - j1)) & mask);
	}
}