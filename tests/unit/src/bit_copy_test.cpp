// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdint>
#include <random>
#include <vector>
#include "apsi/ffield/ffield_elt.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;

namespace
{
    unsigned char get_bit(vector<unsigned char> &vec, size_t position)
    {
        if (position >= (vec.size() * 8))
            throw out_of_range("position");

        size_t byte_idx = position >> 3;
        size_t bit_idx = position & size_t(0x7);
        unsigned char mask = static_cast<unsigned char>(0x1 << bit_idx);
        if (0 == (vec[byte_idx] & mask))
            return 0;

        return 1;
    }
} // namespace

namespace APSITests
{
    TEST(BitCopyTests, bit_copy_test)
    {
        int trials = 1000;
        size_t size = 10;

        std::vector<unsigned char> src(size), dest(size);
        for (int t = 6; t < trials; ++t)
        {
            random_device rd;

            size_t srcOffset = rd() % (size * 4);
            size_t destOffset = rd() % (size * 4);
            size_t bitLength = rd() % (size * 4 - 1) + 1;

            int srcVal = (t & 1) * ~0;
            int destVal = ~srcVal;

            memset(src.data(), srcVal, src.size());
            memset(dest.data(), destVal, dest.size());

            apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

            size_t src_idx = srcOffset;
            size_t dst_idx = 0;

            for (size_t i = 0; i < destOffset; ++i)
            {
                ASSERT_EQ((unsigned char)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }

            for (size_t i = 0; i < bitLength; ++i)
            {
                ASSERT_EQ(get_bit(src, src_idx), get_bit(dest, dst_idx));
                src_idx++;
                dst_idx++;
            }

            size_t rem = size * 8 - destOffset - bitLength;
            for (size_t i = 0; i < rem; ++i)
            {
                ASSERT_EQ((unsigned char)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }
        }
    }
} // namespace APSITests
