// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "apsi/ffield/ffield_elt.h"
#include <vector>

using namespace std;
using namespace apsi;
using namespace apsi::tools;

namespace
{
    block to_block(int i)
    {
        block result = _mm_set_epi64x(0, (u64)i);
        return result;
    }

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
			PRNG prng(to_block(t));

			auto srcOffset = prng.get<u32>() % (size * 4);
			auto destOffset = prng.get<u32>() % (size * 4);
			auto bitLength = prng.get<u32>() % (size * 4 - 1) + 1;

			char srcVal = (t & 1) * ~0;
			char destVal = ~srcVal;

			memset(src.data(), srcVal, src.size());
			memset(dest.data(), destVal, dest.size());

			apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

			u32 src_idx = srcOffset;
			u32 dst_idx = 0;

			for (unsigned i = 0; i < destOffset; ++i)
			{
				ASSERT_EQ((u8)(destVal & 1), get_bit(dest, dst_idx));
				dst_idx++;
			}

			for (unsigned i = 0; i < bitLength; ++i)
			{
				ASSERT_EQ(get_bit(src, src_idx), get_bit(dest, dst_idx));
				src_idx++;
				dst_idx++;
			}

			auto rem = size * 8 - destOffset - bitLength;
			for (unsigned i = 0; i < rem; ++i)
			{
				ASSERT_EQ((u8)(destVal & 1), get_bit(dest, dst_idx));
				dst_idx++;
			}
		}
	}
}
