#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {
    class ItemTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(ItemTests);
        CPPUNIT_TEST(parse_test);
        CPPUNIT_TEST(parse_empty_test);
        CPPUNIT_TEST(parse_diff_base_test);
        CPPUNIT_TEST(parse_non_regular_string_test);
        CPPUNIT_TEST(parse_auto_detect_hex_test);
        CPPUNIT_TEST_SUITE_END();

    public:
        void parse_test();
        void parse_empty_test();
        void parse_diff_base_test();
        void parse_non_regular_string_test();
        void parse_auto_detect_hex_test();
    };
}