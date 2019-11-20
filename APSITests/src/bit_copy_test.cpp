// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "apsi/ffield/ffield_elt.h"
#include <cstdint>
#include <random>
#include <vector>

using namespace std;
using namespace apsi;

namespace
{
    Byte get_bit(vector<Byte>& vec, uint32_t position)
    {
        if (position >= (vec.size() * 8))
            throw out_of_range("position");

        uint32_t byte_idx = position / 8;
        uint32_t bit_idx = position % 8;
        Byte mask = (Byte)(1 << bit_idx);
        if (0 == (vec[byte_idx] & mask))
            return 0;

        return 1;
    }
}

namespace APSITests
{
    TEST(BitCopyTests, bit_copy_test)
    {
        int trials = 1000;
        int size = 10;

        std::vector<Byte> src(size), dest(size);
        for (int t = 6; t < trials; ++t)
        {
            random_device rd;

            uint32_t srcOffset = rd() % (size * 4);
            uint32_t destOffset = rd() % (size * 4);
            uint32_t bitLength = rd() % (size * 4 - 1) + 1;

            char srcVal = (t & 1) * ~0;
            char destVal = ~srcVal;

            memset(src.data(), srcVal, src.size());
            memset(dest.data(), destVal, dest.size());

            apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

            uint32_t src_idx = srcOffset;
            uint32_t dst_idx = 0;

            for (uint32_t i = 0; i < destOffset; ++i)
            {
                ASSERT_EQ((Byte)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }

            for (uint32_t i = 0; i < bitLength; ++i)
            {
                ASSERT_EQ(get_bit(src, src_idx), get_bit(dest, dst_idx));
                src_idx++;
                dst_idx++;
            }

            uint32_t rem = size * 8 - destOffset - bitLength;
            for (uint32_t i = 0; i < rem; ++i)
            {
                ASSERT_EQ((Byte)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }
        }
    }
}
