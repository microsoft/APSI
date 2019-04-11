#pragma once

#include "cppunit/extensions/HelperMacros.h"

namespace APSITests
{
    class StopwatchTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(StopwatchTests);
        CPPUNIT_TEST(single_event_test);
        CPPUNIT_TEST(single_event_multithreading_test);
        CPPUNIT_TEST(stopwatch_block_test);
        CPPUNIT_TEST(stopwatch_multithreading_test);
        CPPUNIT_TEST_SUITE_END();

    public:
        void single_event_test();
        void single_event_multithreading_test();
        void stopwatch_block_test();
        void stopwatch_multithreading_test();
    };
}
