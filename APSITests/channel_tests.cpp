#include "channel_tests.h"
#include "utils.h"
#include <limits>
#include "apsi/result_package.h"
#include "apsi/network/receiverchannel.h"
#include "apsi/network/senderchannel.h"
#include "seal/publickey.h"

using namespace APSITests;
using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::tools;

namespace
{
    zmqpp::context_t ctx_;
    SenderChannel server_(ctx_);
    ReceiverChannel client_(ctx_);
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
    SenderChannel mychannel(ctx_);
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
    vector<u8> empty_client_id;
    ASSERT_THROWS(mychannel.send_get_parameters());
    ASSERT_THROWS(mychannel.send_get_parameters_response(empty_client_id, params));
    ASSERT_THROWS(mychannel.send_preprocess(buff));
    ASSERT_THROWS(mychannel.send_preprocess_response(empty_client_id, buff));
    ASSERT_THROWS(mychannel.send_query(pub_key, relin_keys, query_data));
    ASSERT_THROWS(mychannel.send_query_response(empty_client_id, result));
}

void ChannelTests::DataCountsTest()
{
    SenderChannel svr(ctx_);
    ReceiverChannel clt(ctx_);

    svr.bind("tcp://*:5554");
    clt.connect("tcp://localhost:5554");

    thread clientth([this, &clt]
    {
        this_thread::sleep_for(50ms);

        // This should be SenderOperationType size
        clt.send_get_parameters();

        vector<u8> data1;
        InitU8Vector(data1, 1000);

        // This should be 1000 bytes + SenderOperationType size
        clt.send_preprocess(data1);

        PublicKey pubkey;
        RelinKeys relinkeys;
        map<u64, vector<Ciphertext>> querydata;
        vector<Ciphertext> vec1;
        vector<Ciphertext> vec2;
        Ciphertext txt;

        vec1.push_back(txt);
        vec2.push_back(txt);
        querydata.insert_or_assign(1, vec1);
        querydata.insert_or_assign(2, vec2);

        // This should be:
        // SenderOperationType size
        // 57 for pubkey and 40 for relinkeys
        // size_t size (number of entries in querydata)
        // u64 size * 2 (each entry in querydata)
        // size_t size * 2 (each entry in querydata)
        // Ciphertexts will generate strings of length 57
        clt.send_query(pubkey, relinkeys, querydata);

        SenderResponseGetParameters get_params_resp;
        clt.receive(get_params_resp);

        SenderResponsePreprocess preprocess_resp;
        clt.receive(preprocess_resp);

        SenderResponseQuery query_resp;
        clt.receive(query_resp);
    });

    CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_received());
    CPPUNIT_ASSERT_EQUAL((u64)0, clt.get_total_data_sent());
    CPPUNIT_ASSERT_EQUAL((u64)0, svr.get_total_data_received());
    CPPUNIT_ASSERT_EQUAL((u64)0, svr.get_total_data_sent());

    // get parameters
    shared_ptr<SenderOperation> sender_op;
    svr.receive(sender_op, /* wait_for_message */ true);
    size_t expected_total = sizeof(SenderOperationType);
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_received());

    // preprocess
    svr.receive(sender_op, /* wait_for_message */ true);
    expected_total += 1000;
    expected_total += sizeof(SenderOperationType);
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_received());

    // query
    svr.receive(sender_op, /* wait_for_message */ true);
    expected_total += sizeof(SenderOperationType);
    expected_total += sizeof(size_t) * 3;
    expected_total += sizeof(u64) * 2;
    expected_total += (57 + 40); // pubkey + relinkeys
    expected_total += 57 * 2; // Ciphertexts
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_received());

    // get parameters response
    TableParams table_params{ 10, 1, 2, 40, 12345 };
    CuckooParams cuckoo_params{ 3, 2, 1 };
    SEALParams seal_params;
    PSIParams params(60, true, table_params, cuckoo_params, seal_params);
    svr.send_get_parameters_response(sender_op->client_id, params);
    expected_total = sizeof(SenderOperationType);
    expected_total += sizeof(int) * 3;
    expected_total += sizeof(bool);
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_sent());

    // Preprocess response
    vector<u8> preproc;
    InitU8Vector(preproc, 50);
    svr.send_preprocess_response(sender_op->client_id, preproc);
    expected_total += sizeof(SenderOperationType);
    expected_total += preproc.size();
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_sent());

    // Query response
    vector<ResultPackage> result;
    ResultPackage pkg1 = { 1, 2, "one", "two" };
    ResultPackage pkg2 = { 100, 200, "three", "four" };
    ResultPackage pkg3 = { 20, 40, "hello", "world" };
    result.push_back(pkg1);
    result.push_back(pkg2);
    result.push_back(pkg3);
    svr.send_query_response(sender_op->client_id, result);

    expected_total += sizeof(int) * 6;
    expected_total += 25; // strings
    expected_total += sizeof(SenderOperationType);
    expected_total += sizeof(size_t); // size of vector
    CPPUNIT_ASSERT_EQUAL(expected_total, svr.get_total_data_sent());

    clientth.join();
}

void ChannelTests::SendGetParametersTest()
{
    thread clientth([this]
    {
        client_.send_get_parameters();
    });

    shared_ptr<SenderOperation> sender_op;
    server_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT(sender_op != nullptr);
    CPPUNIT_ASSERT_EQUAL(SOP_get_parameters, sender_op->type);

    clientth.join();
}

void ChannelTests::SendPreprocessTest()
{
    thread clientth([this]
    {
        vector<u8> buff = { 1, 2, 3, 4, 5 };
        client_.send_preprocess(buff);
    });

    shared_ptr<SenderOperation> sender_op;
    server_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT_EQUAL(SOP_preprocess, sender_op->type);
    auto preproc = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);

    CPPUNIT_ASSERT(preproc != nullptr);
    CPPUNIT_ASSERT_EQUAL((size_t)5, preproc->buffer.size());
    CPPUNIT_ASSERT_EQUAL((u8)1, preproc->buffer[0]);
    CPPUNIT_ASSERT_EQUAL((u8)2, preproc->buffer[1]);
    CPPUNIT_ASSERT_EQUAL((u8)3, preproc->buffer[2]);
    CPPUNIT_ASSERT_EQUAL((u8)4, preproc->buffer[3]);
    CPPUNIT_ASSERT_EQUAL((u8)5, preproc->buffer[4]);

    clientth.join();
}

void ChannelTests::SendQueryTest()
{
    thread clientth([this]
    {
        PublicKey pub_key;
        RelinKeys relin_keys;
        map<u64, vector<Ciphertext>> query;

        vector<Ciphertext> vec;
        vec.push_back(Ciphertext());

        query.insert_or_assign(5, vec);

        client_.send_query(pub_key, relin_keys, query);
    });

    shared_ptr<SenderOperation> sender_op;
    server_.receive(sender_op, /* wait_for_message */ true);

    CPPUNIT_ASSERT_EQUAL(SOP_query, sender_op->type);
    auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);

    // For now we can only verify sizes, as all strings received will be empty.
    CPPUNIT_ASSERT(query_op != nullptr);
    CPPUNIT_ASSERT_EQUAL((size_t)1, query_op->query.size());
    CPPUNIT_ASSERT_EQUAL((size_t)1, query_op->query.at(5).size());

    clientth.join();
}

void ChannelTests::SendGetParametersResponseTest()
{
    thread serverth([this]
    {
        shared_ptr<SenderOperation> sender_op;
        server_.receive(sender_op, /* wait_for_message */ true);
        CPPUNIT_ASSERT_EQUAL(SOP_get_parameters, sender_op->type);

        TableParams table_params { 10, 1, 2, 40, 12345 };
        CuckooParams cuckoo_params { 3, 2, 1 };
        SEALParams seal_params;

        unsigned item_bit_count = 60;
        PSIParams params(item_bit_count, true, table_params, cuckoo_params, seal_params);
        params.set_value_bit_count(item_bit_count);

        server_.send_get_parameters_response(sender_op->client_id, params);

        table_params.sender_bin_size = 54321;
        item_bit_count = 80;
        PSIParams params2(item_bit_count, false, table_params, cuckoo_params, seal_params);
        params2.set_value_bit_count(0);

        server_.send_get_parameters_response(sender_op->client_id, params2);
    });

    client_.send_get_parameters();

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
        shared_ptr<SenderOperation> sender_op;
        server_.receive(sender_op, /* wait_for_message */ true);
        CPPUNIT_ASSERT_EQUAL(SOP_preprocess, sender_op->type);

        vector<u8> buffer = { 10, 9, 8, 7, 6 };
        server_.send_preprocess_response(sender_op->client_id, buffer);
    });

    // This buffer will actually be ignored
    vector<u8> buff = { 1 };
    client_.send_preprocess(buff);

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
        shared_ptr<SenderOperation> sender_op;
        server_.receive(sender_op, /* wait_for_message */ true);
        CPPUNIT_ASSERT_EQUAL(SOP_query, sender_op->type);

        vector<ResultPackage> result(4);

        result[0] = ResultPackage { 1, 2, "hello", "world" };
        result[1] = ResultPackage { 3, 4, "one", "two" };
        result[2] = ResultPackage { 11, 10, "", "non empty" };
        result[3] = ResultPackage { 15, 20, "data", "" };

        server_.send_query_response(sender_op->client_id, result);
    });

    PublicKey pubkey;
    RelinKeys relinkeys;
    map<u64, vector<Ciphertext>> querydata;

    // Send empty info, it is ignored
    client_.send_query(pubkey, relinkeys, querydata);

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

void ChannelTests::MultipleClientsTest()
{
    atomic<bool> finished = false;

    thread serverth([this, &finished]
    {
        zmqpp::context_t context;
        SenderChannel sender(context);

        sender.bind("tcp://*:5552");

        while (!finished)
        {
            shared_ptr<SenderOperation> sender_op;
            if (!sender.receive(sender_op))
            {
                this_thread::sleep_for(50ms);
                continue;
            }

            CPPUNIT_ASSERT_EQUAL(SOP_preprocess, sender_op->type);

            // Preprocessing will multiply two numbers and add them to the result
            auto preproc_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
            preproc_op->buffer.resize(3);
            preproc_op->buffer[2] = preproc_op->buffer[0] * preproc_op->buffer[1];

            sender.send_preprocess_response(preproc_op->client_id, preproc_op->buffer);
        }
    });

    vector<thread> clients(5);
    for (unsigned i = 0; i < clients.size(); i++)
    {
        clients[i] = thread([this](unsigned idx)
        {
            zmqpp::context_t context;
            ReceiverChannel recv(context);

            recv.connect("tcp://localhost:5552");

            u8 a = static_cast<u8>(idx) * 2;
            u8 b = a + 1;

            for (unsigned i = 0; i < 5; i++)
            {
                vector<u8> buffer(2);
                buffer[0] = a;
                buffer[1] = b;

                recv.send_preprocess(buffer);

                SenderResponsePreprocess preproc;
                recv.receive(preproc);

                CPPUNIT_ASSERT_EQUAL((size_t)3, preproc.buffer.size());
                CPPUNIT_ASSERT_EQUAL((u8)(a * b), preproc.buffer[2]);
            }

        }, i);
    }

    for (unsigned i = 0; i < clients.size(); i++)
    {
        clients[i].join();
    }

    finished = true;
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
