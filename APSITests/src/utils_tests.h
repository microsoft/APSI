#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {
    class UtilsTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(UtilsTests);
        CPPUNIT_TEST(conversion_to_digits_test);
        CPPUNIT_TEST_SUITE_END();

    public:
        void conversion_to_digits_test();
    };
}
