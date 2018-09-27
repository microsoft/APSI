#include "channel_tests.h"
#include "utils.h"
#include <limits>
#include "apsi/result_package.h"
#include "apsi/network/channel.h"
#include "seal/publickey.h"

using namespace APSITests;
using namespace std;
using namespace seal;
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

void ChannelTests::ThrowWithoutConnectTest()
{
    Channel mychannel(ctx_);
    SenderResponseGetParameters get_params_resp;
    SenderResponsePreprocess preproc_resp;
    SenderResponseQuery query_resp;
    shared_ptr<SenderOperation> sender_op;

    TableParams table_params{ 10, 1, 2, 40, 12345 };
    CuckooParams cuckoo_params{ 3, 2, 1 };
    SEALParams seal_params;

    PSIParams params(60, true, table_params, cuckoo_params, seal_params);

    vector<u8> buff = { 1, 2, 3, 4, 5 };

    PublicKey pub_key;
    RelinKeys relin_keys;
    map<u64, vector<Ciphertext>> query_data;
    vector<ResultPackage> result;

    // Receives
    ASSERT_THROWS(mychannel.receive(get_params_resp));
    ASSERT_THROWS(mychannel.receive(preproc_resp));
    ASSERT_THROWS(mychannel.receive(query_resp));
    ASSERT_THROWS(mychannel.receive(sender_op));

    // Sends
    ASSERT_THROWS(mychannel.send_get_parameters());
    ASSERT_THROWS(mychannel.send_get_parameters_response(params));
    ASSERT_THROWS(mychannel.send_preprocess(buff));
    ASSERT_THROWS(mychannel.send_preprocess_response(buff));
    ASSERT_THROWS(mychannel.send_query(pub_key, relin_keys, query_data));
    ASSERT_THROWS(mychannel.send_query_response(result));
}

void ChannelTests::DataCountsTest()
{
    //Channel svr(ctx_);
    //Channel clt(ctx_);

    //svr.bind("tcp://*:5554");
    //clt.connect("tcp://localhost:5554");

    //thread serverth([this, &svr]
    //{
    //    vector<u8> data1;
    //    InitU8Vector(data1, 1000);

    //    // This should be 1000 bytes
    //    svr.send(data1);

    //    vector<string> data2;
    //    InitStringVector(data2, 100);

    //    // This should be 190 bytes
    //    svr.send(data2);

    //    // 4 bytes
    //    u32 data3 = 10;
    //    svr.send(data3);

    //    // 16 bytes
    //    block data4 = _mm_set_epi64x(1, 1);
    //    svr.send(data4);

    //    string data5 = "Hello world!";
    //    svr.send(data5);

    //    svr.receive(data1);
    //    svr.receive(data2);
    //    svr.receive(data3);
    //    svr.receive(data4);
    //    svr.receive(data5);
    //});

    //vector<u8> data1;
    //vector<string> data2;
    //u32 data3;
    //block data4;
    //string data5;

    //CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_received());
    //CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_sent());

    //clt.receive(data1);
    //CPPUNIT_ASSERT_EQUAL((u64)1000, clt.get_total_data_received());

    //clt.receive(data2);
    //CPPUNIT_ASSERT_EQUAL((u64)1190, clt.get_total_data_received());

    //clt.receive(data3);
    //CPPUNIT_ASSERT_EQUAL((u64)1194, clt.get_total_data_received());

    //clt.receive(data4);
    //CPPUNIT_ASSERT_EQUAL((u64)1210, clt.get_total_data_received());

    //clt.receive(data5);
    //CPPUNIT_ASSERT_EQUAL((u64)1222, clt.get_total_data_received());
    //CPPUNIT_ASSERT_EQUAL((u64)1222, svr.get_total_data_sent());

    //clt.send(data1);
    //CPPUNIT_ASSERT_EQUAL((u64)1000, clt.get_total_data_sent());

    //clt.send(data2);
    //CPPUNIT_ASSERT_EQUAL((u64)1190, clt.get_total_data_sent());

    //clt.send(data3);
    //CPPUNIT_ASSERT_EQUAL((u64)1194, clt.get_total_data_sent());

    //clt.send(data4);
    //CPPUNIT_ASSERT_EQUAL((u64)1210, clt.get_total_data_sent());

    //clt.send(data5);
    //CPPUNIT_ASSERT_EQUAL((u64)1222, clt.get_total_data_sent());

    //serverth.join();
}

void ChannelTests::SendGetParametersTest()
{
    thread serverth([this]
    {
        server_.send_get_parameters();
    });

    shared_ptr<SenderOperation> sender_op;
    client_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT(sender_op != nullptr);
    CPPUNIT_ASSERT_EQUAL(SOP_get_parameters, sender_op->type);

    serverth.join();
}

void ChannelTests::SendPreprocessTest()
{
    thread serverth([this]
    {
        vector<u8> buff = { 1, 2, 3, 4, 5 };
        server_.send_preprocess(buff);
    });

    shared_ptr<SenderOperation> sender_op;
    client_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT_EQUAL(SOP_preprocess, sender_op->type);
    auto preproc = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);

    CPPUNIT_ASSERT(preproc != nullptr);
    CPPUNIT_ASSERT_EQUAL((size_t)5, preproc->buffer.size());
    CPPUNIT_ASSERT_EQUAL((u8)1, preproc->buffer[0]);
    CPPUNIT_ASSERT_EQUAL((u8)2, preproc->buffer[1]);
    CPPUNIT_ASSERT_EQUAL((u8)3, preproc->buffer[2]);
    CPPUNIT_ASSERT_EQUAL((u8)4, preproc->buffer[3]);
    CPPUNIT_ASSERT_EQUAL((u8)5, preproc->buffer[4]);

    serverth.join();
}

void ChannelTests::SendQueryTest()
{
    thread serverth([this]
    {
        PublicKey pub_key;
        RelinKeys relin_keys;
        map<u64, vector<Ciphertext>> query;

        vector<Ciphertext> vec;
        vec.push_back(Ciphertext());

        query.insert_or_assign(5, vec);

        server_.send_query(pub_key, relin_keys, query);
    });

    shared_ptr<SenderOperation> sender_op;
    client_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT_EQUAL(SOP_query, sender_op->type);
    auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);

    // For now we can only verify sizes, as all strings received will be empty.
    CPPUNIT_ASSERT(query_op != nullptr);
    CPPUNIT_ASSERT_EQUAL((size_t)1, query_op->query.size());
    CPPUNIT_ASSERT_EQUAL((size_t)1, query_op->query.at(5).size());

    serverth.join();
}

void ChannelTests::SendGetParametersResponseTest()
{
    thread serverth([this]
    {
        // At the moment the only parameter we care about is sender_bin_size, in table_params
        TableParams table_params { 10, 1, 2, 40, 12345 };
        CuckooParams cuckoo_params { 3, 2, 1 };
        SEALParams seal_params;

        unsigned item_bit_count = 60;
        PSIParams params(item_bit_count, true, table_params, cuckoo_params, seal_params);
        params.set_value_bit_count(item_bit_count);

        server_.send_get_parameters_response(params);

        table_params.sender_bin_size = 54321;
        item_bit_count = 80;
        PSIParams params2(item_bit_count, false, table_params, cuckoo_params, seal_params);
        params2.set_value_bit_count(0);

        server_.send_get_parameters_response(params2);
    });

    SenderResponseGetParameters get_params_response;
    client_.receive(get_params_response);

    CPPUNIT_ASSERT_EQUAL(12345, get_params_response.sender_bin_size);
    CPPUNIT_ASSERT_EQUAL(true,  get_params_response.use_oprf);
    CPPUNIT_ASSERT_EQUAL(60,    get_params_response.item_bit_count);
    CPPUNIT_ASSERT_EQUAL(60,    get_params_response.label_bit_count);

    SenderResponseGetParameters get_params_response2;
    client_.receive(get_params_response2);

    CPPUNIT_ASSERT_EQUAL(54321, get_params_response2.sender_bin_size);
    CPPUNIT_ASSERT_EQUAL(false, get_params_response2.use_oprf);
    CPPUNIT_ASSERT_EQUAL(80,    get_params_response2.item_bit_count);
    CPPUNIT_ASSERT_EQUAL(0,     get_params_response2.label_bit_count);

    serverth.join();
}

void ChannelTests::SendPreprocessResponseTest()
{
    thread serverth([this] 
    {
        vector<u8> buffer = { 10, 9, 8, 7, 6 };
        server_.send_preprocess_response(buffer);
    });

    SenderResponsePreprocess preprocess_response;
    client_.receive(preprocess_response);

    CPPUNIT_ASSERT_EQUAL((size_t)5, preprocess_response.buffer.size());
    CPPUNIT_ASSERT_EQUAL((u8)10, preprocess_response.buffer[0]);
    CPPUNIT_ASSERT_EQUAL((u8)9,  preprocess_response.buffer[1]);
    CPPUNIT_ASSERT_EQUAL((u8)8,  preprocess_response.buffer[2]);
    CPPUNIT_ASSERT_EQUAL((u8)7,  preprocess_response.buffer[3]);
    CPPUNIT_ASSERT_EQUAL((u8)6,  preprocess_response.buffer[4]);

    serverth.join();
}

void ChannelTests::SendQueryResponseTest()
{
    thread serverth([this]
    {
        vector<ResultPackage> result(4);

        result[0] = ResultPackage { 1, 2, "hello", "world" };
        result[1] = ResultPackage { 3, 4, "one", "two" };
        result[2] = ResultPackage { 11, 10, "", "non empty" };
        result[3] = ResultPackage { 15, 20, "data", "" };

        server_.send_query_response(result);
    });

    SenderResponseQuery query_response;
    client_.receive(query_response);

    CPPUNIT_ASSERT_EQUAL((size_t)4, query_response.result.size());

    CPPUNIT_ASSERT_EQUAL(1, query_response.result[0].split_idx);
    CPPUNIT_ASSERT_EQUAL(2, query_response.result[0].batch_idx);
    CPPUNIT_ASSERT(query_response.result[0].data == "hello");
    CPPUNIT_ASSERT(query_response.result[0].label_data == "world");

    CPPUNIT_ASSERT_EQUAL(3, query_response.result[1].split_idx);
    CPPUNIT_ASSERT_EQUAL(4, query_response.result[1].batch_idx);
    CPPUNIT_ASSERT(query_response.result[1].data == "one");
    CPPUNIT_ASSERT(query_response.result[1].label_data == "two");

    CPPUNIT_ASSERT_EQUAL(11, query_response.result[2].split_idx);
    CPPUNIT_ASSERT_EQUAL(10, query_response.result[2].batch_idx);
    CPPUNIT_ASSERT(query_response.result[2].data == "");
    CPPUNIT_ASSERT(query_response.result[2].label_data == "non empty");

    CPPUNIT_ASSERT_EQUAL(15, query_response.result[3].split_idx);
    CPPUNIT_ASSERT_EQUAL(20, query_response.result[3].batch_idx);
    CPPUNIT_ASSERT(query_response.result[3].data == "data");
    CPPUNIT_ASSERT(query_response.result[3].label_data == "");

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
