#pragma once

#include <memory>
#include "cppunit/extensions/HelperMacros.h"
#include "apsi/apsidefines.h"


namespace APSITests
{
    class ChannelTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(ChannelTests);

        CPPUNIT_TEST(ThrowWithoutConnectTest);
        CPPUNIT_TEST(DataCountsTest);
        CPPUNIT_TEST(SendGetParametersTest);
        CPPUNIT_TEST(SendPreprocessTest);
        CPPUNIT_TEST(SendQueryTest);
        CPPUNIT_TEST(SendGetParametersResponseTest);
        CPPUNIT_TEST(SendPreprocessResponseTest);
        CPPUNIT_TEST(SendQueryResponseTest);
        CPPUNIT_TEST(MultipleClientsTest);

        CPPUNIT_TEST_SUITE_END();

    public:
        ChannelTests() = default;
        ~ChannelTests();

        void ThrowWithoutConnectTest();
        void DataCountsTest();
        void SendGetParametersTest();
        void SendPreprocessTest();
        void SendQueryTest();
        void SendGetParametersResponseTest();
        void SendPreprocessResponseTest();
        void SendQueryResponseTest();
        void MultipleClientsTest();

        virtual void setUp();

    private:
        void InitStringVector(std::vector<std::string>& vec, int size);
        void InitU8Vector(std::vector<apsi::u8>&vec, int size);
    };
}
