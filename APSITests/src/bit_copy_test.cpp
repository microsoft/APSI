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
    u8 get_bit(vector<u8>& vec, u32 position)
    {
        if (position >= (vec.size() * 8))
            throw out_of_range("position");

        u32 byte_idx = position / 8;
        u32 bit_idx = position % 8;
        u8 mask = (u8)(1 << bit_idx);
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

        std::vector<u8> src(size), dest(size);
        for (int t = 6; t < trials; ++t)
        {
            random_device rd;

            u32 srcOffset = rd() % (size * 4);
            u32 destOffset = rd() % (size * 4);
            u32 bitLength = rd() % (size * 4 - 1) + 1;

            int srcVal = (t & 1) * ~0;
            int destVal = ~srcVal;

            memset(src.data(), srcVal, src.size());
            memset(dest.data(), destVal, dest.size());

            apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

            u32 src_idx = srcOffset;
            u32 dst_idx = 0;

            for (u32 i = 0; i < destOffset; ++i)
            {
                ASSERT_EQ((u8)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }

            for (u32 i = 0; i < bitLength; ++i)
            {
                ASSERT_EQ(get_bit(src, src_idx), get_bit(dest, dst_idx));
                src_idx++;
                dst_idx++;
            }

            u32 rem = size * 8 - destOffset - bitLength;
            for (u32 i = 0; i < rem; ++i)
            {
                ASSERT_EQ((u8)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }
        }
    }
}
