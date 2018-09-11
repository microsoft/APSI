#pragma once

#include "cppunit/extensions/HelperMacros.h"

namespace APSITests
{

    class CSVReaderTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(CSVReaderTests);
        CPPUNIT_TEST(read_test);
        CPPUNIT_TEST(read_no_label_test);
        CPPUNIT_TEST(read_max_bits_test);
        CPPUNIT_TEST_SUITE_END();

    public:
        void read_test();
        void read_no_label_test();
        void read_max_bits_test();
    };

}
