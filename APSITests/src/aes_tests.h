#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {
    class AESTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(AESTests);
        CPPUNIT_TEST(constructor_test);
        CPPUNIT_TEST(block_test);
        CPPUNIT_TEST_SUITE_END();

    public:
        void constructor_test();
        void block_test();
    };
}
