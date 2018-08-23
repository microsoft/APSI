#include "prng_tests.h"
#include "utils.h"
#include "apsi/tools/prng.h"

#include <vector>
#include <set>

using namespace std;
using namespace APSITests;
using namespace apsi;
using namespace apsi::tools;

void PRNGTests::constructor_test()
{
    block seed;
    PRNG prng1(seed);
    PRNG prng2(seed);

    vector<u8> buffer1(100);
    vector<u8> buffer2(100);
    CPPUNIT_ASSERT_EQUAL((size_t)100, buffer1.size());
    CPPUNIT_ASSERT_EQUAL((size_t)100, buffer2.size());

    // Both should generate the same data 
    prng1.get(buffer1.data(), buffer1.size());
    prng2.get(buffer2.data(), buffer2.size());
    CPPUNIT_ASSERT_EQUAL(0, memcmp(buffer1.data(), buffer2.data(), buffer1.size()));

    // Unseeded should throw
    PRNG prng3;
    ASSERT_THROWS(prng3.get<u64>());

    // After seeding it should not throw
    prng3.set_seed(seed);
    CPPUNIT_ASSERT_NO_THROW(prng3.get<u64>());
}

void PRNGTests::get_test()
{
    block seed1 = _mm_set_epi64x(0, 1);
    block seed2 = _mm_set_epi64x(0, 2);

    PRNG prng1(seed1);
    PRNG prng2(seed2);

    vector<u8> buffer1(100);
    vector<u8> buffer2(100);
    CPPUNIT_ASSERT_EQUAL((size_t)100, buffer1.size());
    CPPUNIT_ASSERT_EQUAL((size_t)100, buffer2.size());

    // Both have different seed so they should generate different numbers
    prng1.get(buffer1.data(), buffer1.size());
    prng2.get(buffer2.data(), buffer2.size());
    CPPUNIT_ASSERT(0 != memcmp(buffer1.data(), buffer2.data(), buffer1.size()));

    // Using the same seed should yield the same numbers
    vector<u8> buffer3(100);
    PRNG prng3(seed2);
    prng3.get(buffer3.data(), buffer3.size());
    CPPUNIT_ASSERT(0 == memcmp(buffer2.data(), buffer3.data(), buffer2.size()));
}

void PRNGTests::get_more_than_buffer()
{
    block seed = _mm_set_epi64x(0, 3);
    PRNG prng(seed, /* buffer_size */ 8);

    vector<u64> buffer(2000);
    std::set<u64> set;

    CPPUNIT_ASSERT_EQUAL((size_t)2000, buffer.size());

    // Get a number of blocks that exceeds the buffer size of the generator.
    prng.get<u64>(buffer.data(), buffer.size());

    // Ensure that all generated blocks are different. This means the PRNG's
    // internal buffer was regenerated correctly.
    for (auto& blk : buffer)
    {
        if (set.find(blk) != set.end())
        {
            CPPUNIT_FAIL("Should not find an existing u64 with same value");
        }

        set.emplace(blk);
    }

    PRNG prng2(seed, /* buffer_size */ 8);
    vector<u64> buffer2(2000);
    
    prng2.get<u64>(buffer2.data(), buffer2.size());

    // Now ensure that a second PRNG generates the same numbers as the first.
    for (auto& blk : buffer2)
    {
        if (set.find(blk) == set.end())
        {
            CPPUNIT_FAIL("Should have found a u64 with the same value");
        }
    }
}