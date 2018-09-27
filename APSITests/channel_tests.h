#pragma once

#include <memory>
#include "cppunit/extensions/HelperMacros.h"
#include "apsi/apsidefines.h"


namespace APSITests
{
    class ChannelTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(ChannelTests);

        CPPUNIT_TEST(SendIntTest);
        CPPUNIT_TEST(SendBlockTest);
        CPPUNIT_TEST(SendIntAsyncTest);
        CPPUNIT_TEST(SendBlockAsyncTest);
        CPPUNIT_TEST(SendStringTest);
        CPPUNIT_TEST(SendStringAsyncTest);
        CPPUNIT_TEST(SendStringVectorTest);
        CPPUNIT_TEST(SendStringVectorAsyncTest);
        CPPUNIT_TEST(SendBufferTest);
        CPPUNIT_TEST(SendBufferAsyncTest);
        CPPUNIT_TEST(SendResultPackageTest);
        CPPUNIT_TEST(SendResultPackageAsyncTest);
        CPPUNIT_TEST(ThrowWithoutConnectTest);
        CPPUNIT_TEST(DataCountsTest);
        CPPUNIT_TEST(SendGetParametersTest);
        CPPUNIT_TEST(SendPreprocessTest);
        CPPUNIT_TEST(SendQueryTest);
        CPPUNIT_TEST(SendGetParametersResponseTest);
        CPPUNIT_TEST(SendPreprocessResponseTest);
        CPPUNIT_TEST(SendQueryResponseTest);

        CPPUNIT_TEST_SUITE_END();

    public:
        ChannelTests() = default;
        ~ChannelTests();

        void SendIntTest();
        void SendBlockTest();
        void SendIntAsyncTest();
        void SendBlockAsyncTest();
        void SendStringTest();
        void SendStringAsyncTest();
        void SendStringVectorTest();
        void SendStringVectorAsyncTest();
        void SendBufferTest();
        void SendBufferAsyncTest();
        void SendResultPackageTest();
        void SendResultPackageAsyncTest();
        void ThrowWithoutConnectTest();
        void DataCountsTest();
        void SendGetParametersTest();
        void SendPreprocessTest();
        void SendQueryTest();
        void SendGetParametersResponseTest();
        void SendPreprocessResponseTest();
        void SendQueryResponseTest();

        virtual void setUp();

    private:
        void InitStringVector(std::vector<std::string>& vec, int size);
        void InitU8Vector(std::vector<apsi::u8>&vec, int size);
    };
}
