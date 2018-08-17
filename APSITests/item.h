#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {
    class ItemTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(ItemTests);
        CPPUNIT_TEST(TestConstruction);
        CPPUNIT_TEST(TestSplits);
        CPPUNIT_TEST(TestConversion);
        CPPUNIT_TEST(TestPermutationHashing);
        CPPUNIT_TEST_SUITE_END();

    public:
        void TestConstruction();
        void TestSplits();
        void TestConversion();
        void TestPermutationHashing();
    };
}