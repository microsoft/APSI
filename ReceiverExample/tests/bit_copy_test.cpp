#include "bit_copy_test.h"
#include "apsi/ffield/ffield_elt.h"

using namespace oc;

void BitCopyTests::bit_copy_test()
{
    int trials = 1000;
    int size = 10;

    std::vector<u8> src(size), dest(size);
    for (int t = 6; t < trials; ++t)
    {
        PRNG prng(toBlock(t));

        auto srcOffset = prng.get<u32>() % (size * 4);
        auto destOffset = prng.get<u32>() % (size * 4);
        auto bitLength = prng.get<u32>() % (size * 4 - 1) + 1;

        char srcVal = (t & 1) * ~0;
        char destVal = ~srcVal;

        //prng.get(src.data(), src.size());
        memset(src.data(), srcVal, src.size());
        memset(dest.data(), destVal, dest.size());

        apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

        oc::BitIterator srcIter((oc::u8*)src.data(), srcOffset);
        oc::BitIterator destIter((oc::u8*)dest.data(), 0);
        oc::BitIterator destEnd((oc::u8*)dest.data(), size * 8);

        for (int i = 0; i < destOffset; ++i)
        {
            CPPUNIT_ASSERT(*destIter == (destVal & 1));

            ++destIter;
        }

        for (int i = 0; i < bitLength; ++i)
        {
            CPPUNIT_ASSERT(srcIter.mByte < src.data() + src.size());
            CPPUNIT_ASSERT(*srcIter == *destIter);

            ++srcIter;
            ++destIter;
        }

        auto rem = size * 8 - destOffset - bitLength;
        for (int i = 0; i < rem; ++i)
        {
            CPPUNIT_ASSERT(*destIter == (destVal & 1));

            ++destIter;
        }
    }
}
