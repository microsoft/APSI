#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests{

    class TestPlainArith : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(TestPlainArith);
        CPPUNIT_TEST(TestMult);
        CPPUNIT_TEST_SUITE_END();

    public:
        void TestMult();
    };
}
