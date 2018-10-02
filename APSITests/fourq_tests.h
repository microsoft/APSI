#pragma once

#include "cppunit/extensions/HelperMacros.h"

namespace APSITests
{
    class FourQTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(FourQTests);

        CPPUNIT_TEST(CreationTest);
        CPPUNIT_TEST(MultiplicationTest);
        CPPUNIT_TEST(InversionTest);
        CPPUNIT_TEST(BufferTest);

        CPPUNIT_TEST_SUITE_END();

    public:
        void CreationTest();
        void MultiplicationTest();
        void InversionTest();
        void BufferTest();
    };
}
