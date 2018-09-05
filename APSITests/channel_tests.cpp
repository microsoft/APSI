#include "channel_tests.h"
#include "utils.h"
#include <limits>
#include "apsi/result_package.h"

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
        int sent;
        server_.receive(sent);
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
        server_.receive(result);
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
        this_thread::sleep_for(50ms);
        server_.send(data);
    });

    int result = 0;
    auto fut = client_.async_receive(result);

    CPPUNIT_ASSERT_EQUAL(0, result);

    fut.get();
    serverth.join();

    CPPUNIT_ASSERT_EQUAL(12345, result);
}

void ChannelTests::SendBlockAsyncTest()
{
    thread serverth([this]
    {
        block data = _mm_set_epi64x(12345, 54321);
        this_thread::sleep_for(50ms);
        server_.send(data);
    });

    block result = zero_block;
    auto fut = client_.async_receive(result);

    CPPUNIT_ASSERT_EQUAL(0, memcmp(&result, &zero_block, sizeof(block)));

    fut.get();
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
        this_thread::sleep_for(50ms);
        server_.send(hello);
    });

    string received = "";
    auto fut = client_.async_receive(received);

    CPPUNIT_ASSERT(received == "");

    string expected = "Hello again";
    fut.get();

    serverth.join();

    CPPUNIT_ASSERT(expected == received);
}

void ChannelTests::SendStringVectorTest()
{
    vector<string> result;
    vector<string> result2;

    thread serverth([this, &result, &result2]
    {
        server_.receive(result);
        server_.receive(result2);
    });

    vector<string> sent;
    InitStringVector(sent, 1000);

    vector<string> empty;

    // Add some data to the result2 vetor. After data is received, it
    // should become empty.
    result2.emplace_back("Hello");
    CPPUNIT_ASSERT_EQUAL((size_t)1, result2.size());

    client_.send(sent);
    client_.send(empty);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL(sent.size(), result.size());
    for (int i = 0; i < 1000; i++)
    {
        CPPUNIT_ASSERT(sent[i] == result[i]);
    }

    CPPUNIT_ASSERT_EQUAL((size_t)0, result2.size());
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

        vector<u8> buff2;
        server_.send(buff2);
    });

    vector<u8> result;
    client_.receive(result);

    vector<u8> result2;
    result2.emplace_back(5);
    CPPUNIT_ASSERT_EQUAL((size_t)1, result2.size());

    client_.receive(result2);

    serverth.join();

    CPPUNIT_ASSERT_EQUAL((size_t)1000, result.size());
    for (int i = 0; i < 1000; i++)
    {
        CPPUNIT_ASSERT_EQUAL((apsi::u8)(i % 0xFF), result[i]);
    }

    CPPUNIT_ASSERT_EQUAL((size_t)0, result2.size());
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

void ChannelTests::SendResultPackageTest()
{
    thread serverth([this]
    {
        ResultPackage pkg;
        pkg.split_idx = 1;
        pkg.batch_idx = 2;
        pkg.data = "This is data";
        pkg.label_data = "Not label data";

        server_.send(pkg);

        ResultPackage pkg2;
        pkg2.split_idx = 3;
        pkg2.batch_idx = 4;
        pkg2.data = "small data";
        pkg2.label_data = "";

        server_.send(pkg2);
    });

    ResultPackage result;
    client_.receive(result);

    CPPUNIT_ASSERT_EQUAL(1, result.split_idx);
    CPPUNIT_ASSERT_EQUAL(2, result.batch_idx);
    CPPUNIT_ASSERT(result.data == "This is data");
    CPPUNIT_ASSERT(result.label_data == "Not label data");

    ResultPackage result2;
    client_.receive(result2);

    CPPUNIT_ASSERT_EQUAL(3, result2.split_idx);
    CPPUNIT_ASSERT_EQUAL(4, result2.batch_idx);
    CPPUNIT_ASSERT(result2.data == "small data");
    CPPUNIT_ASSERT(result2.label_data.empty());

    serverth.join();
}

void ChannelTests::SendResultPackageAsyncTest()
{
    thread serverth([this]
    {
        ResultPackage pkg;

        pkg.split_idx = 5;
        pkg.batch_idx = 6;
        pkg.data = "data 1";
        pkg.label_data = "label 1";

        this_thread::sleep_for(50ms);

        server_.send(pkg);
    });

    ResultPackage result;
    result.batch_idx = 0;
    result.split_idx = 0;

    future<void> fut = client_.async_receive(result);

    // At this point nothing should have been received.
    CPPUNIT_ASSERT_EQUAL(0, result.split_idx);
    CPPUNIT_ASSERT_EQUAL(0, result.batch_idx);
    CPPUNIT_ASSERT(result.data.empty());
    CPPUNIT_ASSERT(result.data.empty());

    fut.get();

    // Now data should be there.
    CPPUNIT_ASSERT_EQUAL(5, result.split_idx);
    CPPUNIT_ASSERT_EQUAL(6, result.batch_idx);
    CPPUNIT_ASSERT(result.data == "data 1");
    CPPUNIT_ASSERT(result.label_data == "label 1");

    serverth.join();
}

void ChannelTests::ThrowWithoutConnectTest()
{
    Channel mychannel(ctx_);
    int result;
    string str;
    vector<u8> buff;
    vector<string> buff2;

    // Receives
    ASSERT_THROWS(mychannel.receive(result));
    ASSERT_THROWS(mychannel.receive(str));
    ASSERT_THROWS(mychannel.receive(buff));
    ASSERT_THROWS(mychannel.receive(buff2));

    // Sends
    ASSERT_THROWS(mychannel.send(result));
    ASSERT_THROWS(mychannel.send(str));
    ASSERT_THROWS(mychannel.send(buff));
    ASSERT_THROWS(mychannel.send(buff2));
}

void ChannelTests::DataCountsTest()
{
    Channel svr(ctx_);
    Channel clt(ctx_);

    svr.bind("tcp://*:5554");
    clt.connect("tcp://localhost:5554");

    thread serverth([this, &svr]
    {
        vector<u8> data1;
        InitU8Vector(data1, 1000);

        // This should be 1000 bytes
        svr.send(data1);

        vector<string> data2;
        InitStringVector(data2, 100);

        // This should be 190 bytes
        svr.send(data2);

        // 4 bytes
        u32 data3 = 10;
        svr.send(data3);

        // 16 bytes
        block data4 = _mm_set_epi64x(1, 1);
        svr.send(data4);

        string data5 = "Hello world!";
        svr.send(data5);

        svr.receive(data1);
        svr.receive(data2);
        svr.receive(data3);
        svr.receive(data4);
        svr.receive(data5);
    });

    vector<u8> data1;
    vector<string> data2;
    u32 data3;
    block data4;
    string data5;

    CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_received());
    CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_sent());

    clt.receive(data1);
    CPPUNIT_ASSERT_EQUAL((u64)1000, clt.get_total_data_received());

    clt.receive(data2);
    CPPUNIT_ASSERT_EQUAL((u64)1190, clt.get_total_data_received());

    clt.receive(data3);
    CPPUNIT_ASSERT_EQUAL((u64)1194, clt.get_total_data_received());

    clt.receive(data4);
    CPPUNIT_ASSERT_EQUAL((u64)1210, clt.get_total_data_received());

    clt.receive(data5);
    CPPUNIT_ASSERT_EQUAL((u64)1222, clt.get_total_data_received());
    CPPUNIT_ASSERT_EQUAL((u64)1222, svr.get_total_data_sent());

    clt.send(data1);
    CPPUNIT_ASSERT_EQUAL((u64)1000, clt.get_total_data_sent());

    clt.send(data2);
    CPPUNIT_ASSERT_EQUAL((u64)1190, clt.get_total_data_sent());

    clt.send(data3);
    CPPUNIT_ASSERT_EQUAL((u64)1194, clt.get_total_data_sent());

    clt.send(data4);
    CPPUNIT_ASSERT_EQUAL((u64)1210, clt.get_total_data_sent());

    clt.send(data5);
    CPPUNIT_ASSERT_EQUAL((u64)1222, clt.get_total_data_sent());

    serverth.join();
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
