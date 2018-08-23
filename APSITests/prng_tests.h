#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests
{
    class PRNGTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(PRNGTests);
        CPPUNIT_TEST(constructor_test);
        CPPUNIT_TEST(get_test);
        CPPUNIT_TEST(get_more_than_buffer);
        CPPUNIT_TEST_SUITE_END();

    public:
        void constructor_test();
        void get_test();
        void get_more_than_buffer();
    };
}
