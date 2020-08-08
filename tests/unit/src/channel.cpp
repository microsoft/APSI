// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <string>
#include <thread>
#include <utility>

// SEAL
#include "seal/keygenerator.h"
#include "seal/publickey.h"

// APSI
#include "apsi/network/network_channel.h"
#include "apsi/util/utils.h"

#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::util;
using namespace apsi::network;

namespace APSITests
{
    namespace
    {
        SenderChannel server_;
        ReceiverChannel client_;

        void InitStringVector(vector<string> &vec, int size)
        {
            vec.resize(size);

            for (int i = 0; i < size; i++)
            {
                stringstream ss;
                ss << i;
                vec[i] = ss.str();
            }
        }

        void InitByteVector(vector<SEAL_BYTE> &vec, int size)
        {
            vec.resize(size);

            for (int i = 0; i < size; i++)
            {
                vec[i] = static_cast<SEAL_BYTE>(i % 0xFF);
            }
        }

        template <typename... Ts>
        vector<SEAL_BYTE> CreateByteVector(Ts &&... args)
        {
            return { SEAL_BYTE(forward<Ts>(args))... };
        }
    } // namespace

    class ChannelTests : public ::testing::Test
    {
    protected:
        ChannelTests()
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

        ~ChannelTests()
        {
            // Do not disconnect, as the Constructor / Destructor is called for every test.
            // if (client_.is_connected())
            //	client_.disconnect();

            // if (server_.is_connected())
            //	server_.disconnect();
        }
    };

    TEST_F(ChannelTests, ThrowWithoutConnectTest)
    {
        // SenderChannel and ReceiverChannel are identical for the purposes of this test
        SenderChannel mychannel;

        // Receives
        ASSERT_THROW(mychannel.receive_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_network_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_response(), runtime_error);
        ASSERT_THROW(mychannel.receive_result_package(nullptr), runtime_error);

        // Sends
        ASSERT_THROW(mychannel.send(make_unique<ResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<NetworkResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationResponseParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<NetworkSenderOperationResponse>()), runtime_error);
    }

    TEST_F(ChannelTests, DataCountsTest)
    {
        SenderChannel svr;
        ReceiverChannel clt;

        svr.bind("tcp://*:5554");
        clt.connect("tcp://localhost:5554");

        thread clientth([this, &clt] {
            this_thread::sleep_for(50ms);

            auto sop_parms = make_unique<SenderOperationParms>();
            sop_parms->
            unique_ptr<SenderOperation> sop = make_unique<SenderOperationParms>();

            clt.apsi::network::Channel::send()

            vector<SEAL_BYTE> data1;
            InitByteVector(data1, 1000);

            // This should be 1000 bytes + SenderOperationType size
            clt.send_preprocess(data1);

            EncryptionParameters enc_params(scheme_type::BFV);
            enc_params.set_plain_modulus(64ul);
            enc_params.set_poly_modulus_degree(4096);
            enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
            shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
            KeyGenerator key_gen(context);

            stringstream ss;
            Serializable<RelinKeys> ser_relinkeys = key_gen.relin_keys();
            ser_relinkeys.save(ss, compr_mode_type::none);
            string relinkeys_str = ss.str();
            ASSERT_EQ(relinkeys_str.length(), 197010);

            Ciphertext ct(context);
            ss = stringstream();
            ct.save(ss, compr_mode_type::none);
            string ct_str = ss.str();
            ASSERT_EQ(ct_str.length(), 105);

            map<uint64_t, vector<string>> querydata;
            vector<string> vec1;
            vec1.push_back(ct_str);
            vector<string> vec2;
            vec2.push_back(ct_str);
            querydata.insert_or_assign(1, vec1);
            querydata.insert_or_assign(2, vec2);

            // This should be:
            // SenderOperationType size
            // 8425 for relinkeys
            // uint64_t size (number of entries in querydata)
            // uint64_t size * 2 (each entry in querydata)
            // uint64_t size * 2 (each entry in querydata)
            // Ciphertexts will generate strings of length 105
            clt.send_query(relinkeys_str, querydata);

            SenderResponseGetParameters get_params_resp;
            clt.receive(get_params_resp);

            SenderResponsePreprocess preprocess_resp;
            clt.receive(preprocess_resp);

            SenderResponseQuery query_resp;
            clt.receive(query_resp);

            ResultPackage pkg;
            clt.receive(pkg);
            clt.receive(pkg);
            clt.receive(pkg);
        });

        ASSERT_EQ((uint64_t)0, clt.get_total_data_received());
        ASSERT_EQ((uint64_t)0, clt.get_total_data_sent());
        ASSERT_EQ((uint64_t)0, svr.get_total_data_received());
        ASSERT_EQ((uint64_t)0, svr.get_total_data_sent());

        // get parameters
        shared_ptr<SenderOperation> sender_op;
        svr.receive(sender_op, [> wait_for_message <] true);
        size_t expected_total = sizeof(uint32_t); // SenderOperationType
        ASSERT_EQ(expected_total, svr.get_total_data_received());

        // preprocess
        svr.receive(sender_op, [> wait_for_message <] true);
        expected_total += 1000;
        expected_total += sizeof(uint32_t); // SenderOperationType
        ASSERT_EQ(expected_total, svr.get_total_data_received());

        // query
        svr.receive(sender_op, [> wait_for_message <] true);
        expected_total += sizeof(uint32_t); // SenderOperationType
        expected_total += sizeof(uint64_t) * 3;
        expected_total += sizeof(uint64_t) * 2;
        expected_total += 197010;  // relinkeys
        expected_total += 105 * 2; // Ciphertexts
        ASSERT_EQ(expected_total, svr.get_total_data_received());

        // get parameters response
        PSIParams::PSIConfParams psiconf_params{ 12345, 20, 60, 120, 10, true, true };
        PSIParams::TableParams table_params{ 10, 1, 2, 10, 40 };
        PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
        PSIParams::FFieldParams ffield_params{ 321, 8 };
        PSIParams::SEALParams seal_params;
        vector<Modulus> smv = CoeffModulus::BFVDefault(4096);
        seal_params.encryption_params.set_poly_modulus_degree(4096);
        seal_params.encryption_params.set_plain_modulus(5119);
        seal_params.encryption_params.set_coeff_modulus(smv);
        PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, ffield_params);

        svr.send_get_parameters_response(sender_op->client_id, params);
        expected_total = sizeof(uint32_t); // SenderOperationType
        expected_total += sizeof(PSIParams::PSIConfParams);
        expected_total += sizeof(PSIParams::TableParams);
        expected_total += sizeof(PSIParams::CuckooParams);
        expected_total += sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t); // sizeof(PSIParams::SEALParams);
        expected_total += sizeof(PSIParams::FFieldParams);
        ASSERT_EQ(expected_total, svr.get_total_data_sent());

        // Preprocess response
        vector<SEAL_BYTE> preproc;
        InitByteVector(preproc, 50);
        svr.send_preprocess_response(sender_op->client_id, preproc);
        expected_total += sizeof(uint32_t); // SenderOperationType
        expected_total += preproc.size();
        ASSERT_EQ(expected_total, svr.get_total_data_sent());

        // Query response
        vector<ResultPackage> result;
        ResultPackage pkg1 = { 1, 2, "one", "two" };
        ResultPackage pkg2 = { 100, 200, "three", "four" };
        ResultPackage pkg3 = { 20, 40, "hello", "world" };
        result.push_back(pkg1);
        result.push_back(pkg2);
        result.push_back(pkg3);
        svr.send_query_response(sender_op->client_id, 3);
        svr.send(sender_op->client_id, pkg1);
        svr.send(sender_op->client_id, pkg2);
        svr.send(sender_op->client_id, pkg3);

        expected_total += sizeof(int64_t) * 6;
        expected_total += 25;               // strings
        expected_total += sizeof(uint32_t); // SenderOperationType
        expected_total += sizeof(uint64_t); // size of vector
        ASSERT_EQ(expected_total, svr.get_total_data_sent());

        clientth.join();
    }

    //TEST_F(ChannelTests, SendGetParametersTest)
    //{
        //thread clientth([this] { client_.send_get_parameters(); });

        //shared_ptr<SenderOperation> sender_op;
        //server_.receive(sender_op, [> wait_for_message <] true);

        //ASSERT_TRUE(sender_op != nullptr);
        //ASSERT_EQ(SOP_get_parameters, sender_op->type);

        //clientth.join();
    //}

    //TEST_F(ChannelTests, SendPreprocessTest)
    //{
        //thread clientth([this] {
            //vector<SEAL_BYTE> buff = CreateByteVector(1, 2, 3, 4, 5);
            //client_.send_preprocess(buff);
        //});

        //shared_ptr<SenderOperation> sender_op;
        //server_.receive(sender_op, [> wait_for_message <] true);

        //ASSERT_EQ(SOP_preprocess, sender_op->type);
        //auto preproc = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);

        //ASSERT_TRUE(preproc != nullptr);
        //ASSERT_EQ((size_t)5, preproc->buffer.size());
        //ASSERT_EQ((unsigned char)1, (unsigned char)preproc->buffer[0]);
        //ASSERT_EQ((unsigned char)2, (unsigned char)preproc->buffer[1]);
        //ASSERT_EQ((unsigned char)3, (unsigned char)preproc->buffer[2]);
        //ASSERT_EQ((unsigned char)4, (unsigned char)preproc->buffer[3]);
        //ASSERT_EQ((unsigned char)5, (unsigned char)preproc->buffer[4]);

        //clientth.join();
    //}

    //TEST_F(ChannelTests, SendQueryTest)
    //{
        //thread clientth([this] {
            //EncryptionParameters enc_params(scheme_type::BFV);
            //enc_params.set_plain_modulus(64ul);
            //enc_params.set_poly_modulus_degree(4096);
            //enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
            //shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
            //KeyGenerator key_gen(context);

            //PublicKey pub_key = key_gen.public_key();
            //RelinKeys relin_keys = key_gen.relin_keys_local();
            //stringstream ss;
            //relin_keys.save(ss);
            //string relin_keys_str = ss.str();

            //map<uint64_t, vector<string>> query;

            //vector<string> vec;
            //vec.push_back(string());

            //query.insert_or_assign(5, vec);

            //client_.send_query(relin_keys_str, query);
        //});

        //shared_ptr<SenderOperation> sender_op;
        //server_.receive(sender_op, [> wait_for_message <] true);

        //ASSERT_EQ(SOP_query, sender_op->type);
        //auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);

        //// For now we can only verify sizes, as all strings received will be empty.
        //ASSERT_TRUE(query_op != nullptr);
        //ASSERT_EQ((size_t)1, query_op->query.size());
        //ASSERT_EQ((size_t)1, query_op->query.at(5).size());

        //clientth.join();
    //}

    //TEST_F(ChannelTests, SendGetParametersResponseTest)
    //{
        //thread serverth([this] {
            //shared_ptr<SenderOperation> sender_op;
            //server_.receive(sender_op, [> wait_for_message <] true);
            //ASSERT_EQ(SOP_get_parameters, sender_op->type);

            //PSIParams::PSIConfParams psiconf_params{ 12345, 50, 60, 120, 40, true, false };
            //PSIParams::TableParams table_params{ 10, 1, 2, 10, 40, false };
            //PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
            //PSIParams::FFieldParams ffield_params{ 678910, 8 };
            //PSIParams::SEALParams seal_params;
            //seal_params.max_supported_degree = 25;
            //seal_params.encryption_params.set_plain_modulus(5119);
            //seal_params.encryption_params.set_poly_modulus_degree(4096);
            //vector<Modulus> coeff_modulus =
                //CoeffModulus::BFVDefault(seal_params.encryption_params.poly_modulus_degree());
            //seal_params.encryption_params.set_coeff_modulus(coeff_modulus);

            //PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, ffield_params);

            //server_.send_get_parameters_response(sender_op->client_id, params);

            //psiconf_params.sender_size = 54321;
            //psiconf_params.item_bit_count = 80;
            //psiconf_params.use_labels = false;
            //PSIParams params2(psiconf_params, table_params, cuckoo_params, seal_params, ffield_params);

            //server_.send_get_parameters_response(sender_op->client_id, params2);
        //});

        //client_.send_get_parameters();
        //serverth.join();

        //SenderResponseGetParameters get_params_response;
        //client_.receive(get_params_response);

        //ASSERT_EQ((uint64_t)12345, get_params_response.psiconf_params.sender_size);
        //ASSERT_EQ(true, get_params_response.psiconf_params.use_labels);
        //ASSERT_EQ(false, get_params_response.psiconf_params.use_fast_membership);
        //ASSERT_EQ((uint32_t)60, get_params_response.psiconf_params.item_bit_count);
        //ASSERT_EQ(size_t(120), get_params_response.psiconf_params.item_bit_length_used_after_oprf);
        //ASSERT_EQ((uint32_t)40, get_params_response.psiconf_params.num_chunks);
        //ASSERT_EQ((uint32_t)50, get_params_response.psiconf_params.sender_bin_size);
        //ASSERT_EQ((uint32_t)10, get_params_response.table_params.log_table_size);
        //ASSERT_EQ((uint32_t)1, get_params_response.table_params.window_size);
        //ASSERT_EQ((uint32_t)2, get_params_response.table_params.split_count);
        //ASSERT_EQ((uint32_t)10, get_params_response.table_params.split_size);
        //ASSERT_EQ((uint32_t)40, get_params_response.table_params.binning_sec_level);
        //ASSERT_FALSE(get_params_response.table_params.use_dynamic_split_count);
        //ASSERT_EQ((uint32_t)3, get_params_response.cuckoo_params.hash_func_count);
        //ASSERT_EQ((uint32_t)2, get_params_response.cuckoo_params.hash_func_seed);
        //ASSERT_EQ((uint32_t)1, get_params_response.cuckoo_params.max_probe);
        //ASSERT_EQ((uint64_t)678910, get_params_response.ffield_params.characteristic);
        //ASSERT_EQ((uint32_t)8, get_params_response.ffield_params.degree);
        //ASSERT_EQ((uint32_t)25, get_params_response.seal_params.max_supported_degree);
        //ASSERT_EQ((uint64_t)5119, get_params_response.seal_params.encryption_params.plain_modulus().value());
        //ASSERT_EQ((size_t)4096, get_params_response.seal_params.encryption_params.poly_modulus_degree());
        //ASSERT_EQ((size_t)3, get_params_response.seal_params.encryption_params.coeff_modulus().size());
        //ASSERT_EQ(
            //(uint64_t)0x0000000FFFFEE001, get_params_response.seal_params.encryption_params.coeff_modulus()[0].value());
        //ASSERT_EQ(
            //(uint64_t)0x0000000FFFFC4001, get_params_response.seal_params.encryption_params.coeff_modulus()[1].value());
        //ASSERT_EQ(
            //(uint64_t)0x0000001FFFFE0001, get_params_response.seal_params.encryption_params.coeff_modulus()[2].value());

        //SenderResponseGetParameters get_params_response2;
        //client_.receive(get_params_response2);

        //ASSERT_EQ((uint64_t)54321, get_params_response2.psiconf_params.sender_size);
        //ASSERT_EQ(false, get_params_response2.psiconf_params.use_labels);
        //ASSERT_EQ((uint32_t)80, get_params_response2.psiconf_params.item_bit_count);
        //ASSERT_EQ((uint32_t)10, get_params_response2.table_params.log_table_size);
        //ASSERT_EQ((uint32_t)1, get_params_response2.table_params.window_size);
        //ASSERT_EQ((uint32_t)2, get_params_response2.table_params.split_count);
        //ASSERT_EQ((uint32_t)40, get_params_response2.table_params.binning_sec_level);
        //ASSERT_EQ((uint32_t)3, get_params_response2.cuckoo_params.hash_func_count);
        //ASSERT_EQ((uint32_t)2, get_params_response2.cuckoo_params.hash_func_seed);
        //ASSERT_EQ((uint32_t)1, get_params_response2.cuckoo_params.max_probe);
        //ASSERT_EQ((uint64_t)678910, get_params_response2.ffield_params.characteristic);
        //ASSERT_EQ((uint32_t)8, get_params_response2.ffield_params.degree);
        //ASSERT_EQ((uint64_t)5119, get_params_response2.seal_params.encryption_params.plain_modulus().value());
        //ASSERT_EQ((size_t)4096, get_params_response2.seal_params.encryption_params.poly_modulus_degree());
        //ASSERT_EQ((size_t)3, get_params_response2.seal_params.encryption_params.coeff_modulus().size());
        //ASSERT_EQ(
            //(uint64_t)0x0000000FFFFEE001,
            //get_params_response2.seal_params.encryption_params.coeff_modulus()[0].value());
        //ASSERT_EQ(
            //(uint64_t)0x0000000FFFFC4001,
            //get_params_response2.seal_params.encryption_params.coeff_modulus()[1].value());
        //ASSERT_EQ(
            //(uint64_t)0x0000001FFFFE0001,
            //get_params_response2.seal_params.encryption_params.coeff_modulus()[2].value());
    //}

    //TEST_F(ChannelTests, SendPreprocessResponseTest)
    //{
        //thread serverth([this] {
            //shared_ptr<SenderOperation> sender_op;
            //server_.receive(sender_op, [> wait_for_message <] true);
            //ASSERT_EQ(SOP_preprocess, sender_op->type);

            //vector<SEAL_BYTE> buffer = CreateByteVector(10, 9, 8, 7, 6);
            //server_.send_preprocess_response(sender_op->client_id, buffer);
        //});

        //// This buffer will actually be ignored
        //vector<SEAL_BYTE> buff = CreateByteVector(1);
        //client_.send_preprocess(buff);

        //SenderResponsePreprocess preprocess_response;
        //client_.receive(preprocess_response);

        //ASSERT_EQ((size_t)5, preprocess_response.buffer.size());
        //ASSERT_EQ((unsigned char)10, (unsigned char)preprocess_response.buffer[0]);
        //ASSERT_EQ((unsigned char)9, (unsigned char)preprocess_response.buffer[1]);
        //ASSERT_EQ((unsigned char)8, (unsigned char)preprocess_response.buffer[2]);
        //ASSERT_EQ((unsigned char)7, (unsigned char)preprocess_response.buffer[3]);
        //ASSERT_EQ((unsigned char)6, (unsigned char)preprocess_response.buffer[4]);

        //serverth.join();
    //}

    //TEST_F(ChannelTests, SendQueryResponseTest)
    //{
        //thread serverth([this] {
            //shared_ptr<SenderOperation> sender_op;
            //server_.receive(sender_op, [> wait_for_message <] true);
            //ASSERT_EQ(SOP_query, sender_op->type);

            //vector<ResultPackage> result(4);

            //result[0] = ResultPackage{ 1, 2, "hello", "world" };
            //result[1] = ResultPackage{ 3, 4, "one", "two" };
            //result[2] = ResultPackage{ 11, 10, "", "non empty" };
            //result[3] = ResultPackage{ 15, 20, "data", "" };

            //server_.send_query_response(sender_op->client_id, 4);
            //server_.send(sender_op->client_id, result[0]);
            //server_.send(sender_op->client_id, result[1]);
            //server_.send(sender_op->client_id, result[2]);
            //server_.send(sender_op->client_id, result[3]);
        //});

        //EncryptionParameters enc_params(scheme_type::BFV);
        //enc_params.set_plain_modulus(64ul);
        //enc_params.set_poly_modulus_degree(4096);
        //enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
        //shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
        //KeyGenerator key_gen(context);

        //PublicKey pubkey = key_gen.public_key();
        //RelinKeys relinkeys = key_gen.relin_keys_local();
        //stringstream ss;
        //relinkeys.save(ss);
        //string relinkeys_str = ss.str();

        //map<uint64_t, vector<string>> querydata;

        //// Send empty info, it is ignored
        //client_.send_query(relinkeys_str, querydata);

        //SenderResponseQuery query_response;
        //client_.receive(query_response);

        //ASSERT_EQ((uint64_t)4, query_response.package_count);

        //ResultPackage pkg;
        //client_.receive(pkg);

        //ASSERT_EQ(2, pkg.bundle_idx);
        //ASSERT_TRUE(pkg.data == "hello");
        //ASSERT_TRUE(pkg.label_data == "world");

        //client_.receive(pkg);

        //ASSERT_EQ(4, pkg.bundle_idx);
        //ASSERT_TRUE(pkg.data == "one");
        //ASSERT_TRUE(pkg.label_data == "two");

        //client_.receive(pkg);

        //ASSERT_EQ(10, pkg.bundle_idx);
        //ASSERT_TRUE(pkg.data == "");
        //ASSERT_TRUE(pkg.label_data == "non empty");

        //client_.receive(pkg);

        //ASSERT_EQ(20, pkg.bundle_idx);
        //ASSERT_TRUE(pkg.data == "data");
        //ASSERT_TRUE(pkg.label_data == "");

        //serverth.join();
    //}

    //TEST_F(ChannelTests, MultipleClientsTest)
    //{
        //atomic<bool> finished = false;

        //thread serverth([this, &finished] {
            //SenderChannel sender;

            //sender.bind("tcp://*:5552");

            //while (!finished)
            //{
                //shared_ptr<SenderOperation> sender_op;
                //if (!sender.receive(sender_op))
                //{
                    //this_thread::sleep_for(50ms);
                    //continue;
                //}

                //ASSERT_EQ(SOP_preprocess, sender_op->type);

                //// Preprocessing will multiply two numbers and add them to the result
                //auto preproc_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
                //preproc_op->buffer.resize(3);
                //preproc_op->buffer[2] =
                    //(SEAL_BYTE)((unsigned char)preproc_op->buffer[0] * (unsigned char)preproc_op->buffer[1]);

                //sender.send_preprocess_response(preproc_op->client_id, preproc_op->buffer);
            //}
        //});

        //vector<thread> clients(5);
        //for (size_t i = 0; i < clients.size(); i++)
        //{
            //clients[i] = thread(
                //[this](size_t idx) {
                    //ReceiverChannel recv;

                    //recv.connect("tcp://localhost:5552");

                    //unsigned char a = static_cast<unsigned char>(idx) * 2;
                    //unsigned char b = a + 1;

                    //for (uint32_t i = 0; i < 5; i++)
                    //{
                        //vector<SEAL_BYTE> buffer = CreateByteVector(a, b);

                        //recv.send_preprocess(buffer);

                        //SenderResponsePreprocess preproc;
                        //recv.receive(preproc);

                        //ASSERT_EQ((size_t)3, preproc.buffer.size());
                        //ASSERT_EQ((unsigned char)(a * b), (unsigned char)preproc.buffer[2]);
                    //}
                //},
                //i);
        //}

        //for (size_t i = 0; i < clients.size(); i++)
        //{
            //clients[i].join();
        //}

        //finished = true;
        //serverth.join();
    //}

    //TEST_F(ChannelTests, SendResultPackageTest)
    //{
        //thread serverth([this] {
            //shared_ptr<SenderOperation> sender_op;
            //server_.receive(sender_op, [> wait_for_message <] true);
            //ASSERT_EQ(SOP_get_parameters, sender_op->type);

            //ResultPackage pkg;
            //pkg.bundle_idx = 2;
            //pkg.data = "This is data";
            //pkg.label_data = "Not label data";

            //server_.send(sender_op->client_id, pkg);

            //ResultPackage pkg2;
            //pkg2.bundle_idx = 4;
            //pkg2.data = "small data";
            //pkg2.label_data = "";

            //server_.send(sender_op->client_id, pkg2);
        //});

        //client_.send_get_parameters();

        //ResultPackage result;
        //client_.receive(result);

        //ASSERT_EQ(2, result.bundle_idx);
        //ASSERT_TRUE(result.data == "This is data");
        //ASSERT_TRUE(result.label_data == "Not label data");

        //ResultPackage result2;
        //client_.receive(result2);

        //ASSERT_EQ(4, result2.bundle_idx);
        //ASSERT_TRUE(result2.data == "small data");
        //ASSERT_TRUE(result2.label_data.empty());

        //serverth.join();
    //}
} // namespace APSITests
