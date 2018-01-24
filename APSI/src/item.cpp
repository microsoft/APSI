
#include "item.h"
#include <stdexcept>
#include "apsidefines.h"
#include "cryptoTools/Crypto/RandomOracle.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace apsi::tools;

namespace apsi
{

    Item::Item(uint64_t *pointer)
    {
		value_[0] = pointer[0];
		value_[1] = pointer[1];
    }

    Item::Item(const string &str)
    {
        operator=(str);
    }

    Item::Item(uint64_t item)
    {
        operator=(item);
    }

	Item::Item(const cuckoo::block & item)
	{
		value_ = *(std::array<u64, 2>*)&item;
	}

	Item& Item::operator =(uint64_t assign)
	{
		value_[0] = assign;
		value_[1] = 0;

		return *this;
	}

	Item& Item::operator =(const cuckoo::block& assign)
	{
		value_ = *(std::array<u64,2>*)&assign;

		return *this;
	}

    Item& Item::operator =(const string &str)
    {
		if (str.size() > sizeof(value_))
		{

			oc::RandomOracle oracl(sizeof(block));
			oracl.Update(str.data(), str.size());
			oracl.Final(value_);
		}
		else
		{
			value_[0] = 0;
			value_[1] = 0;
			memcpy((void*)str.data(), value_.data(), str.size());
		}

        return *this;
    }

    Item& Item::operator =(const Item &assign)
    {
        for (int i = 0; i < value_.size(); i++)
            value_[i] = assign.value_[i];
        return *this;
    }


    ExFieldElement Item::to_exfield_element(std::shared_ptr<ExField> exfield, int bit_length)
    {
        ExFieldElement ring_item(exfield);
        to_exfield_element(ring_item, bit_length);
        return ring_item;
    }

    void Item::to_exfield_element(ExFieldElement &ring_item, int bit_length)
    {
        shared_ptr<ExField> &exfield = ring_item.ex_field();
        int split_length = exfield->coeff_modulus().bit_count() - 1; // Should minus 1 to avoid wrapping around p
        int split_index_bound = (bit_length + split_length - 1) / split_length;
        int j = 0;
        for (; j < (exfield->coeff_count() - 1) && j < split_index_bound; j++)
            ring_item.pointer(j)[0] = item_part(j, split_length);
        for (; j < (exfield->coeff_count() - 1); j++)
            ring_item.pointer(j)[0] = 0;
    }

    uint64_t Item::item_part(uint32_t i, uint32_t split_length)
    {
        int i1 = (i * split_length) >> 6,
            i2 = ((i + 1) * split_length) >> 6,
            j1 = (i * split_length) & 0x3F,  // mod 64
            j2 = ((i + 1) * split_length) & 0x3F;  // mod 64
#ifdef _DEBUG
        if (split_length > 64 || i2 > value_.size())
            throw invalid_argument("invalid split_length, or index out of range.");
#endif
        int mask = (1 << split_length) - 1;
        if (i1 == i2 || i2 == value_.size())
            return (value_[i1] >> j1) & mask;
        else
            return ((value_[i1] >> j1) & mask) | ((value_[i2] << (64 - j1)) & mask);
    }

    void Item::save(std::ostream &stream) const
    {
        stream.write(reinterpret_cast<const char*>(&value_), sizeof(value_));
    }

    void Item::load(std::istream &stream)
    {
        stream.read(reinterpret_cast<char*>(&value_), sizeof(value_));
    }
}
