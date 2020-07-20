// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cctype>
#include <stdexcept>
#include <gsl/span>
#include <seal/util/blake2.h>
#include <seal/util/common.h>
#include <seal/util/uintcore.h>
#include "apsi/item.h"

using namespace std;
using namespace seal;
using namespace kuku;

namespace apsi
{
    namespace
    {
        uint32_t Item::muladd(uint32_t item[4], uint32_t mul, uint32_t add)
        {
            uint64_t temp = 0;

            temp = static_cast<uint64_t>(item[0]) * static_cast<uint64_t>(mul) + static_cast<uint64_t>(add);
            item[0] = static_cast<uint32_t>(temp);

            temp = static_cast<uint64_t>(item[1]) * static_cast<uint64_t>(mul) + static_cast<uint64_t>(temp >> 32);
            item[1] = static_cast<uint32_t>(temp);

            temp = static_cast<uint64_t>(item[2]) * static_cast<uint64_t>(mul) + static_cast<uint64_t>(temp >> 32);
            item[2] = static_cast<uint32_t>(temp);

            temp = static_cast<uint64_t>(item[3]) * static_cast<uint64_t>(mul) + static_cast<uint64_t>(temp >> 32);
            item[3] = static_cast<uint32_t>(temp);

            return static_cast<uint32_t>(temp >> 32);
        }
    }

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

    Item &Item::operator=(uint64_t assign)
    {
        value_[0] = assign;
        value_[1] = 0;
        return *this;
    }

    Item &Item::operator=(const item_type &assign)
    {
        value_ = assign;
        return *this;
    }

    Item::Item(const item_type &item)
    {
        operator=(item);
    }

    Item &Item::operator=(const string &str)
    {
        if (str.size() > sizeof(value_))
        {
            // Use BLAKE2b as random oracle
            blake2(
                reinterpret_cast<unsigned char *>(&value_), sizeof(value_),
                reinterpret_cast<const unsigned char *>(str.data()), str.size(), nullptr, 0);
        }
        else
        {
            value_[0] = 0;
            value_[1] = 0;
            memcpy(value_.data(), str.data(), str.size());
        }

        return *this;
    }

    Item &Item::operator=(const Item &assign)
    {
        for (size_t i = 0; i < value_.size(); i++)
            value_[i] = assign.value_[i];
        return *this;
    }

    FFieldElt Item::to_ffield_element(FField ffield, size_t bit_length)
    {
        FFieldElt ring_item(ffield);
        to_ffield_element(ring_item, bit_length);
        return ring_item;
    }

    uint64_t item_part(const array<uint64_t, 2> &value_, size_t i, size_t split_length)
    {
        size_t i1 = (i * split_length) >> 6;
        size_t i2 = ((i + 1) * split_length) >> 6;
        size_t j1 = (i * split_length) & 0x3F;
        size_t j2 = ((i + 1) * split_length) & 0x3F;
#ifdef _DEBUG
        if (split_length > 64 || i2 > value_.size())
        {
            throw invalid_argument("invalid split_length, or index out of range");
        }
#endif
        uint64_t mask = (uint64_t(1) << split_length) - 1;
        if ((i1 == i2) || (i2 == value_.size()))
        {
            return (value_[i1] >> j1) & mask;
        }
        else
        {
            return ((value_[i1] >> j1) & mask) | ((value_[i2] << (64 - j2)) & mask);
        }
    }

    void Item::to_ffield_element(FFieldElt &ring_item, size_t bit_length)
    {
        auto ffield = ring_item.field();

        // Should minus 1 to avoid wrapping around p
        // Hao: why?
        size_t split_length = static_cast<size_t>(ffield.characteristic().bit_count()) - 1;

        // How many coefficients do we need in the FFieldElement
        size_t split_index_bound = (bit_length + split_length - 1) / split_length;

        for (size_t j = 0; j < static_cast<size_t>(ffield.degree()) && j < split_index_bound; j++)
        {
            uint64_t coeff = item_part(value_, j, split_length);
            ring_item.set_coeff(j, coeff);
        }
    }

    void Item::parse(const string &input, uint32_t base)
    {
        if (base != 10 && base != 16)
            throw invalid_argument("Only base 10 and 16 are supported.");

        // Use 32 bit numbers so we can handle overflow easily
        uint32_t item[4] = { 0 };
        uint32_t rem = 0;

        for (const auto &chr : input)
        {
            if (iswspace(static_cast<wint_t>(chr)))
                continue;

            if (base == 10 && !isdigit(chr))
                break;

            if (base == 16 && !util::is_hex_char(chr))
                break;

            rem = muladd(item, base, static_cast<uint32_t>(util::hex_to_nibble(chr)));
            if (rem != 0)
            {
                throw invalid_argument("Input represents more than 128 bits");
            }
        }

        value_[0] = (static_cast<uint64_t>(item[1]) << 32) + item[0];
        value_[1] = (static_cast<uint64_t>(item[3]) << 32) + item[2];
    }

    void Item::parse(const string &input)
    {
        string num = input;
        uint32_t base = 10;

        // Trim initial whitespace
        num.erase(num.begin(), find_if(num.begin(), num.end(), [](int ch) { return !isspace(ch); }));

        if (num.length() >= 2 && num[0] == '0' && (num[1] == 'x' || num[1] == 'X'))
        {
            // Remove the '0x'
            num.erase(num.begin());
            num.erase(num.begin());

            base = 16;
        }

        parse(num, base);
    }
} // namespace apsi
