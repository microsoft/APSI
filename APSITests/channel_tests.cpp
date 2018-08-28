#include "channel_tests.h"

using namespace APSITests;
using namespace std;
using namespace apsi;
using namespace apsi::network;

namespace
{
    zmqpp::context_t ctx_;
    Channel server_(ctx_);
    Channel client_(ctx_);
}

ChannelTests::~ChannelTests()
{
    if (client_.is_connected())
        client_.disconnect();

    if (server_.is_connected())
        server_.disconnect();
}

void ChannelTests::setUp()
{
    if (!server_.is_connected())
    {
        server_.bind("tcp://*:5555");
    }

    if (!client_.is_connected())
    {
        client_.connect("tcp://localhost:5555");
    }
}

void ChannelTests::SendIntTest()
{
    int result = 0;
    thread serverth([this, &result]
    {
        int sent = server_.receive<int>();
        result = sent;
    });

    int data = 5;
    client_.send(data);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(data, result);
}

void ChannelTests::SendBlockTest()
{
    block blk = _mm_set_epi64x(0, 10);
    block result = _mm_set_epi64x(0, 0);

    thread serverth([this, &result]
    {
        result = server_.receive<block>();
    });

    block data = _mm_set_epi64x(0, 10);
    client_.send(data);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(0, memcmp(&result, &data, sizeof(block)));
}

void ChannelTests::SendIntAsyncTest()
{
    thread serverth([this]
    {
        int data = 12345;
        server_.send(data);
    });

    auto fut = client_.async_receive<int>();
    int result = fut.get();

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(12345, result);
}

void ChannelTests::SendBlockAsyncTest()
{
    thread serverth([this]
    {
        block data = _mm_set_epi64x(12345, 54321);
        server_.send(data);
    });

    auto fut = client_.async_receive<block>();
    block result = fut.get();
    block expected = _mm_set_epi64x(12345, 54321);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(0, memcmp(&expected, &result, sizeof(block)));
}

void ChannelTests::SendStringTest()
{
    thread serverth([this]
    {
        string hello = "Hello world";
        server_.send(hello);
    });

    string expected = "Hello world";
    string received;
    client_.receive(received);

    serverth.join();

    CPPUNIT_ASSERT(expected == received);
}

void ChannelTests::SendStringAsyncTest()
{
    thread serverth([this]
    {
        string hello = "Hello again";
        server_.send(hello);
    });

    auto fut = client_.async_receive();
    string expected = "Hello again";
    string received = fut.get();

    serverth.join();

    CPPUNIT_ASSERT(expected == received);
}

void ChannelTests::SendStringVectorTest()
{
    vector<string> result;

    thread serverth([this, &result]
    {
        vector<string> received;
        server_.receive(received);
        result = received;
    });

    vector<string> sent;
    InitStringVector(sent, 1000);

    client_.send(sent);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(sent.size(), result.size());
    for (int i = 0; i < 1000; i++)
    {
        CPPUNIT_ASSERT(sent[i] == result[i]);
    }
}

void ChannelTests::SendStringVectorAsyncTest()
{
    thread serverth([this]
    {
        vector<string> sent;
        InitStringVector(sent, 1000);

        this_thread::sleep_for(50ms);
        server_.send(sent);
    });

    vector<string> result;
    auto fut = client_.async_receive(result);

    // For now result should be empty
    CPPUNIT_ASSERT_EQUAL((size_t)0, result.size());

    fut.get();
    serverth.join();

    // Now we should have data.
    CPPUNIT_ASSERT_EQUAL((size_t)1000, result.size());
}

void ChannelTests::SendBufferTest()
{
    thread serverth([this]
    {
        vector<u8> buff;
        InitU8Vector(buff, 1000);

        server_.send(buff);
    });

    vector<u8> result;
    client_.receive(result);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL((size_t)1000, result.size());
    for (int i = 0; i < 1000; i++)
    {
        CPPUNIT_ASSERT_EQUAL((apsi::u8)(i % 0xFF), result[i]);
    }
}

void ChannelTests::SendBufferAsyncTest()
{
    thread serverth([this]
    {
        vector<u8> buff;
        InitU8Vector(buff, 1000);
        this_thread::sleep_for(50ms);
        server_.send(buff);
    });

    vector<u8> result;
    auto fut = client_.async_receive(result);

    // Result should still be empty
    CPPUNIT_ASSERT_EQUAL((size_t)0, result.size());

    fut.get();
    serverth.join();

    // Now we should have data
    CPPUNIT_ASSERT_EQUAL((size_t)1000, result.size());
    for (int i = 0; i < 1000; i++)
    {
        CPPUNIT_ASSERT_EQUAL((apsi::u8)(i % 0xFF), result[i]);
    }
}

void ChannelTests::InitStringVector(vector<string>& vec, int size)
{
    vec.resize(size);

    for (int i = 0; i < size; i++)
    {
        stringstream ss;
        ss << i;
        vec[i] = ss.str();
    }
}

void ChannelTests::InitU8Vector(vector<u8>& vec, int size)
{
    vec.resize(size);

    for (int i = 0; i < size; i++)
    {
        vec[i] = i % 0xFF;
    }
}
