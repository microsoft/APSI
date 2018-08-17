#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {

class BitCopyTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(BitCopyTests);
    CPPUNIT_TEST(bit_copy_test);
    CPPUNIT_TEST_SUITE_END();

public:
    void bit_copy_test();
};

}
