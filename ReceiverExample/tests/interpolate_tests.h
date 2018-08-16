#pragma once

#include <cppunit/extensions/HelperMacros.h>

class InterpolateTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(InterpolateTests);
    CPPUNIT_TEST(u64_interpolate_test);
    CPPUNIT_TEST_SUITE_END();

public:
    void u64_interpolate_test();
};

