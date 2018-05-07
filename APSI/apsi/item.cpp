#include "item.h"
#include <stdexcept>
#include "apsidefines.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "seal/util/uintcore.h"
#include "seal/util/common.h"

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

    void bitPrint(u8* data, int length, int offset = 0)
    {
        oc::BitIterator iter(data, offset);

        for (int i = 0; i < length; ++i)
        {
            std::cout << int(*iter);
            ++iter;
        }
        std::cout << std::endl;
    }


    template<typename T>
    typename std::enable_if<std::is_pod<T>::value>::type
        encode(FFieldElt &ring_item, oc::span<const T> value, int bit_length)
    {
        oc::span<const oc::u8> v2((oc::u8*)value.data(), value.size() * sizeof(T));

        // Should minus 1 to avoid wrapping around p
        int split_length = seal::util::get_significant_bit_count(ring_item.field()->ch()) - 1;

        // How many coefficients do we need in the ExFieldElement
        int split_index_bound = (bit_length + split_length - 1) / split_length;

        static_assert(std::is_pod<_ffield_elt_coeff_t>::value, "must be pod type");
        _ffield_elt_coeff_t coeff = 0;
        oc::span<oc::u8> temp_span((oc::u8*)&coeff, sizeof(_ffield_elt_coeff_t));

        auto end = std::min<int>(ring_item.field()->d(), split_index_bound);
        for (int j = 0; j < end; j++)
        {
            // copy the j'th set of bits in value to temp
            details::copy_with_bit_offset(v2, j * split_length, split_length, temp_span);
            //std::cout << j << " " << temp << std::endl;

            std::cout << std::string(j * split_length, ' ');
            bitPrint((u8*)& coeff, split_length);
            // the the coeff
            ring_item.set_coeff(j, coeff);
        }
    }



    uint64_t item_part(const std::array<oc::u64, 2>& value_, uint32_t i, uint32_t split_length)
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
        //ring_item.encode(oc::span<u64>{value_}, bit_length);
       // bitPrint((u8*)value_.data(), bit_length);



        auto exfield = ring_item.field();

        // Should minus 1 to avoid wrapping around p
        int split_length = get_significant_bit_count(exfield->ch()) - 1;

        // How many coefficients do we need in the ExFieldElement
        int split_index_bound = (bit_length + split_length - 1) / split_length;

        //for (int j = 0; j < exfield->d() && j < split_index_bound; j++)
        //{
        //    std::cout << std::string(split_length - 1, ' ') << '^';
        //}
        //std::cout << std::endl;

        int j = 0;
        for (; j < exfield->d() && j < split_index_bound; j++)
        {
            auto coeff = item_part(value_, j, split_length);


            //std::cout << std::string(j * split_length, ' ');
            //bitPrint((u8*)& coeff, split_length);
            //std::cout << j << " " << coeff << std::endl;

            ring_item.set_coeff(j, coeff);
        }


        //auto copy = ring_item;
        //copy.encode(oc::span<const u64>{value_}, bit_length);
        //if (copy != ring_item)
        //    throw std::runtime_error(LOCATION);

        // // Fill remaining ExFieldElement coefficients with zero
        // for (; j < (exfield->coeff_count() - 1); j++)
        // {
        //     *ring_item.pointer(j) = 0;
        // }
    }

//
    void Item::save(ostream &stream) const
    {
        stream.write(reinterpret_cast<const char*>(&value_), sizeof(value_));
    }

    void Item::load(istream &stream)
    {
        stream.read(reinterpret_cast<char*>(&value_), sizeof(value_));
    }
}
