// STD
#include <stdexcept>

// GSL
#include <gsl/span>

// APSI
#include "apsi/item.h"
#include "apsi/apsidefines.h"

// SEAL
#include "seal/util/uintcore.h"
#include "seal/util/common.h"

// crypto++
#include "cryptopp/sha3.h"


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
        value_ = *(array<u64, 2>*)&item;
    }

    Item &Item::operator =(uint64_t assign)
    {
        value_[0] = assign;
        value_[1] = 0;

        return *this;
    }

    Item &Item::operator =(const cuckoo::block& assign)
    {
        value_ = *(array<u64,2>*)&assign;

        return *this;
    }

    Item &Item::operator =(const string &str)
    {
        if (str.size() > sizeof(value_))
        {
            // Use SHA3 as random oracle
            CryptoPP::SHA3_256 sha3;
            sha3.Update(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());
            sha3.TruncatedFinal(reinterpret_cast<CryptoPP::byte*>(&value_), sizeof(value_));
        }
        else
        {
            value_[0] = 0;
            value_[1] = 0;
            memcpy((void*)str.data(), value_.data(), str.size());
        }

        return *this;
    }

    Item &Item::operator =(const Item &assign)
    {
        for (int i = 0; i < value_.size(); i++)
            value_[i] = assign.value_[i];
        return *this;
    }

    FFieldElt Item::to_exfield_element(const shared_ptr<FField> &exfield, int bit_length)
    {
        FFieldElt ring_item(exfield);
        to_exfield_element(ring_item, bit_length);
        return ring_item;
    }

    uint64_t item_part(const std::array<apsi::u64, 2>& value_, uint32_t i, uint32_t split_length)
    {
        int i1 = (i * split_length) >> 6,
            i2 = ((i + 1) * split_length) >> 6,
            j1 = (i * split_length) & 0x3F,  // mod 64
            j2 = ((i + 1) * split_length) & 0x3F;  // mod 64
#ifdef _DEBUG
        if (split_length > 64 || i2 > value_.size())
        {
            throw invalid_argument("invalid split_length, or index out of range");
        }
#endif
        uint64_t mask = (1ULL << split_length) - 1;
        if ((i1 == i2) || (i2 == value_.size()))
        {
            return (value_[i1] >> j1) & mask;
        }
        else
        {
            return ((value_[i1] >> j1) & mask) | ((value_[i2] << (64 - j1)) & mask);
        }
    }


    void Item::to_exfield_element(FFieldElt &ring_item, int bit_length)
    {
        auto exfield = ring_item.field();

        // Should minus 1 to avoid wrapping around p
        int split_length = get_significant_bit_count(exfield->ch()) - 1;

        // How many coefficients do we need in the ExFieldElement
        int split_index_bound = (bit_length + split_length - 1) / split_length;

        int j = 0;
        for (; static_cast<unsigned>(j) < exfield->d() && j < split_index_bound; j++)
        {
            auto coeff = item_part(value_, j, split_length);
            ring_item.set_coeff(j, coeff);
        }
    }

    void Item::save(ostream &stream) const
    {
        stream.write(reinterpret_cast<const char*>(&value_), sizeof(value_));
    }

    void Item::load(istream &stream)
    {
        stream.read(reinterpret_cast<char*>(&value_), sizeof(value_));
    }
}
