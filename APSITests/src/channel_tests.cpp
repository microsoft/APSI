// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "utils.h"
#include <limits>
#include <thread>
#include "apsi/result_package.h"
#include "apsi/network/receiverchannel.h"
#include "apsi/network/senderchannel.h"
#include "seal/publickey.h"
#include "seal/keygenerator.h"


using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::tools;


namespace
{
    SenderChannel server_;
    ReceiverChannel client_;

	void InitStringVector(vector<string>& vec, int size)
	{
		vec.resize(size);

		for (int i = 0; i < size; i++)
		{
			stringstream ss;
			ss << i;
			vec[i] = ss.str();
		}
	}

	void InitU8Vector(vector<u8>& vec, int size)
	{
		vec.resize(size);

		for (int i = 0; i < size; i++)
		{
			vec[i] = i % 0xFF;
		}
	}
}

namespace APSITests
{
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
			//if (client_.is_connected())
			//	client_.disconnect();

			//if (server_.is_connected())
			//	server_.disconnect();
		}
	};

	TEST_F(ChannelTests, ThrowWithoutConnectTest)
	{
		SenderChannel mychannel;
		SenderResponseGetParameters get_params_resp;
		SenderResponsePreprocess preproc_resp;
		SenderResponseQuery query_resp;
		shared_ptr<SenderOperation> sender_op;

		PSIParams::PSIConfParams psiconf_params{ 60, true, true, true, 12345, 120, 10, 20 };
		PSIParams::TableParams table_params{ 10, 1, 2, 10, 40 };
		PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
		PSIParams::SEALParams seal_params;
		PSIParams::ExFieldParams exfield_params;
		PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);

		vector<u8> buff = { 1, 2, 3, 4, 5 };

		PublicKey pub_key;
		RelinKeys relin_keys;
		map<u64, vector<SeededCiphertext>> query_data;
        seed128 relin_keys_seeds;

		// Receives
		ASSERT_ANY_THROW(mychannel.receive(get_params_resp));
		ASSERT_ANY_THROW(mychannel.receive(preproc_resp));
		ASSERT_ANY_THROW(mychannel.receive(query_resp));
		ASSERT_ANY_THROW(mychannel.receive(sender_op));

		// Sends
		vector<u8> empty_client_id;
		ASSERT_ANY_THROW(mychannel.send_get_parameters());
		ASSERT_ANY_THROW(mychannel.send_get_parameters_response(empty_client_id, params));
		ASSERT_ANY_THROW(mychannel.send_preprocess(buff));
		ASSERT_ANY_THROW(mychannel.send_preprocess_response(empty_client_id, buff));
		ASSERT_ANY_THROW(mychannel.send_query(relin_keys, query_data, relin_keys_seeds));
		ASSERT_ANY_THROW(mychannel.send_query_response(empty_client_id, 10));
	}

	TEST_F(ChannelTests, DataCountsTest)
	{
		SenderChannel svr;
		ReceiverChannel clt;

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

				EncryptionParameters enc_params(scheme_type::BFV);
				enc_params.set_plain_modulus(64ul);
				enc_params.set_poly_modulus_degree(1024);
				enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
				shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
				KeyGenerator key_gen(context);

				PublicKey pubkey = key_gen.public_key();
				RelinKeys relinkeys = key_gen.relin_keys();
				map<u64, vector<SeededCiphertext>> querydata;
                seed128 relin_keys_seed;
				vector<SeededCiphertext> vec1;
				vector<SeededCiphertext> vec2;
				SeededCiphertext txt;

				vec1.push_back(txt);
				vec2.push_back(txt);
				querydata.insert_or_assign(1, vec1);
				querydata.insert_or_assign(2, vec2);

				// This should be:
				// SenderOperationType size
				// 73 for pubkey and 44 for relinkeys
				// size_t size (number of entries in querydata)
				// u64 size * 2 (each entry in querydata)
				// size_t size * 2 (each entry in querydata)
				// Ciphertexts will generate strings of length 73
				clt.send_query(relinkeys, querydata, relin_keys_seed);

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

		ASSERT_EQ((u64)0, clt.get_total_data_received());
		ASSERT_EQ((u64)0, clt.get_total_data_sent());
		ASSERT_EQ((u64)0, svr.get_total_data_received());
		ASSERT_EQ((u64)0, svr.get_total_data_sent());

		// get parameters
		shared_ptr<SenderOperation> sender_op;
		svr.receive(sender_op, /* wait_for_message */ true);
		size_t expected_total = sizeof(SenderOperationType);
		ASSERT_EQ(expected_total, svr.get_total_data_received());

		// preprocess
		svr.receive(sender_op, /* wait_for_message */ true);
		expected_total += 1000;
		expected_total += sizeof(SenderOperationType);
		ASSERT_EQ(expected_total, svr.get_total_data_received());

		// query
		svr.receive(sender_op, /* wait_for_message */ true);
		expected_total += sizeof(SenderOperationType);
		expected_total += sizeof(size_t) * 3;
		expected_total += sizeof(u64) * 2;
		expected_total += 16537; // pubkey + relinkeys
		expected_total += 73 * 2; // Ciphertexts
		ASSERT_EQ(expected_total, svr.get_total_data_received());

		// get parameters response
		PSIParams::PSIConfParams psiconf_params{ 60, true, true, true, 12345, 120, 10, 20 };
		PSIParams::TableParams table_params{ 10, 1, 2, 10, 40 };
		PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
		PSIParams::ExFieldParams exfield_params{ 321, 8 };
		PSIParams::SEALParams seal_params;
		seal_params.decomposition_bit_count = 10;
		vector<SmallModulus> smv = CoeffModulus::BFVDefault(4096);
		seal_params.encryption_params.set_poly_modulus_degree(4096);
		seal_params.encryption_params.set_plain_modulus(5119);
		seal_params.encryption_params.set_coeff_modulus(smv);
		PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);

		svr.send_get_parameters_response(sender_op->client_id, params);
		expected_total = sizeof(SenderOperationType);
		expected_total += sizeof(PSIParams::PSIConfParams);
		expected_total += sizeof(PSIParams::TableParams);
		expected_total += sizeof(PSIParams::CuckooParams);
		expected_total += sizeof(PSIParams::SEALParams);
		expected_total += sizeof(PSIParams::ExFieldParams);
		ASSERT_EQ(expected_total, svr.get_total_data_sent());

		// Preprocess response
		vector<u8> preproc;
		InitU8Vector(preproc, 50);
		svr.send_preprocess_response(sender_op->client_id, preproc);
		expected_total += sizeof(SenderOperationType);
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

		expected_total += sizeof(int) * 6;
		expected_total += 25; // strings
		expected_total += sizeof(SenderOperationType);
		expected_total += sizeof(size_t); // size of vector
		ASSERT_EQ(expected_total, svr.get_total_data_sent());

		clientth.join();
	}

	TEST_F(ChannelTests, SendGetParametersTest)
	{
		thread clientth([this]
			{
				client_.send_get_parameters();
			});

		shared_ptr<SenderOperation> sender_op;
		server_.receive(sender_op, /* wait_for_message */ true);

		ASSERT_TRUE(sender_op != nullptr);
		ASSERT_EQ(SOP_get_parameters, sender_op->type);

		clientth.join();
	}

	TEST_F(ChannelTests, SendPreprocessTest)
	{
		thread clientth([this]
			{
				vector<u8> buff = { 1, 2, 3, 4, 5 };
				client_.send_preprocess(buff);
			});

		shared_ptr<SenderOperation> sender_op;
		server_.receive(sender_op, /* wait_for_message */ true);

		ASSERT_EQ(SOP_preprocess, sender_op->type);
		auto preproc = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);

		ASSERT_TRUE(preproc != nullptr);
		ASSERT_EQ((size_t)5, preproc->buffer.size());
		ASSERT_EQ((u8)1, preproc->buffer[0]);
		ASSERT_EQ((u8)2, preproc->buffer[1]);
		ASSERT_EQ((u8)3, preproc->buffer[2]);
		ASSERT_EQ((u8)4, preproc->buffer[3]);
		ASSERT_EQ((u8)5, preproc->buffer[4]);

		clientth.join();
	}

	TEST_F(ChannelTests, SendQueryTest)
	{
		thread clientth([this]
			{
				EncryptionParameters enc_params(scheme_type::BFV);
				enc_params.set_plain_modulus(64ul);
				enc_params.set_poly_modulus_degree(1024);
				enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
				shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
				KeyGenerator key_gen(context);

				PublicKey pub_key = key_gen.public_key();
				RelinKeys relin_keys = key_gen.relin_keys();

				map<u64, vector<SeededCiphertext>> query;
                seed128 relin_keys_seed;

				vector<SeededCiphertext> vec;
				vec.push_back(SeededCiphertext());

				query.insert_or_assign(5, vec);

				client_.send_query(relin_keys, query, relin_keys_seed);
			});

		shared_ptr<SenderOperation> sender_op;
		server_.receive(sender_op, /* wait_for_message */ true);

		ASSERT_EQ(SOP_query, sender_op->type);
		auto query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);

		// For now we can only verify sizes, as all strings received will be empty.
		ASSERT_TRUE(query_op != nullptr);
		ASSERT_EQ((size_t)1, query_op->query.size());
		ASSERT_EQ((size_t)1, query_op->query.at(5).size());

		clientth.join();
	}

	TEST_F(ChannelTests, SendGetParametersResponseTest)
	{
		thread serverth([this]
			{
				shared_ptr<SenderOperation> sender_op;
				server_.receive(sender_op, /* wait_for_message */ true);
				ASSERT_EQ(SOP_get_parameters, sender_op->type);

				PSIParams::PSIConfParams psiconf_params{ 60, true, true, false, 12345, 120, 40, 50 };
				PSIParams::TableParams table_params{ 10, 1, 2, 10, 40 };
				PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
				PSIParams::ExFieldParams exfield_params{ 678910, 8 };
				PSIParams::SEALParams seal_params;
				seal_params.decomposition_bit_count = 30;
                seal_params.max_supported_degree = 25;
				seal_params.encryption_params.set_plain_modulus(5119);
				seal_params.encryption_params.set_poly_modulus_degree(4096);
				vector<SmallModulus> coeff_modulus = CoeffModulus::BFVDefault(seal_params.encryption_params.poly_modulus_degree());
				seal_params.encryption_params.set_coeff_modulus(coeff_modulus);

				PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);

				server_.send_get_parameters_response(sender_op->client_id, params);

				psiconf_params.sender_size = 54321;
				psiconf_params.item_bit_count = 80;
				psiconf_params.use_oprf = false;
				psiconf_params.use_labels = false;
				PSIParams params2(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);

				server_.send_get_parameters_response(sender_op->client_id, params2);
			});

		client_.send_get_parameters();
		serverth.join();

		SenderResponseGetParameters get_params_response;
		client_.receive(get_params_response);

		ASSERT_EQ((u64)12345, get_params_response.psiconf_params.sender_size);
		ASSERT_EQ(true, get_params_response.psiconf_params.use_oprf);
		ASSERT_EQ(true, get_params_response.psiconf_params.use_labels);
        ASSERT_EQ(false, get_params_response.psiconf_params.use_fast_membership);
		ASSERT_EQ((unsigned)60, get_params_response.psiconf_params.item_bit_count);
        ASSERT_EQ((unsigned)120, get_params_response.psiconf_params.item_bit_length_used_after_oprf);
        ASSERT_EQ((unsigned)40, get_params_response.psiconf_params.num_chunks);
        ASSERT_EQ((unsigned)50, get_params_response.psiconf_params.sender_bin_size);
		ASSERT_EQ((unsigned)10, get_params_response.table_params.log_table_size);
		ASSERT_EQ((unsigned)1, get_params_response.table_params.window_size);
		ASSERT_EQ((unsigned)2, get_params_response.table_params.split_count);
        ASSERT_EQ((unsigned)10, get_params_response.table_params.split_size);
		ASSERT_EQ((unsigned)40, get_params_response.table_params.binning_sec_level);
		ASSERT_EQ((unsigned)3, get_params_response.cuckoo_params.hash_func_count);
		ASSERT_EQ((unsigned)2, get_params_response.cuckoo_params.hash_func_seed);
		ASSERT_EQ((unsigned)1, get_params_response.cuckoo_params.max_probe);
		ASSERT_EQ((u64)678910, get_params_response.exfield_params.characteristic);
		ASSERT_EQ((unsigned)8, get_params_response.exfield_params.degree);
		ASSERT_EQ((unsigned)30, get_params_response.seal_params.decomposition_bit_count);
        ASSERT_EQ((unsigned)25, get_params_response.seal_params.max_supported_degree);
		ASSERT_EQ((u64)5119, get_params_response.seal_params.encryption_params.plain_modulus().value());
		ASSERT_EQ((size_t)4096, get_params_response.seal_params.encryption_params.poly_modulus_degree());
		ASSERT_EQ((size_t)3, get_params_response.seal_params.encryption_params.coeff_modulus().size());
		ASSERT_EQ((u64)0x0000000FFFFEE001, get_params_response.seal_params.encryption_params.coeff_modulus()[0].value());
        ASSERT_EQ((u64)0x0000000FFFFC4001, get_params_response.seal_params.encryption_params.coeff_modulus()[1].value());
        ASSERT_EQ((u64)0x0000001FFFFE0001, get_params_response.seal_params.encryption_params.coeff_modulus()[2].value());


		SenderResponseGetParameters get_params_response2;
		client_.receive(get_params_response2);

		ASSERT_EQ((u64)54321, get_params_response2.psiconf_params.sender_size);
		ASSERT_EQ(false, get_params_response2.psiconf_params.use_oprf);
		ASSERT_EQ(false, get_params_response2.psiconf_params.use_labels);
		ASSERT_EQ((unsigned)80, get_params_response2.psiconf_params.item_bit_count);
		ASSERT_EQ((unsigned)10, get_params_response2.table_params.log_table_size);
		ASSERT_EQ((unsigned)1, get_params_response2.table_params.window_size);
		ASSERT_EQ((unsigned)2, get_params_response2.table_params.split_count);
		ASSERT_EQ((unsigned)40, get_params_response2.table_params.binning_sec_level);
		ASSERT_EQ((unsigned)3, get_params_response2.cuckoo_params.hash_func_count);
		ASSERT_EQ((unsigned)2, get_params_response2.cuckoo_params.hash_func_seed);
		ASSERT_EQ((unsigned)1, get_params_response2.cuckoo_params.max_probe);
		ASSERT_EQ((u64)678910, get_params_response2.exfield_params.characteristic);
		ASSERT_EQ((unsigned)8, get_params_response2.exfield_params.degree);
		ASSERT_EQ((unsigned)30, get_params_response2.seal_params.decomposition_bit_count);
		ASSERT_EQ((u64)5119, get_params_response2.seal_params.encryption_params.plain_modulus().value());
		ASSERT_EQ((size_t)4096, get_params_response2.seal_params.encryption_params.poly_modulus_degree());
		ASSERT_EQ((size_t)3, get_params_response2.seal_params.encryption_params.coeff_modulus().size());
		ASSERT_EQ((u64)0x0000000FFFFEE001, get_params_response2.seal_params.encryption_params.coeff_modulus()[0].value());
        ASSERT_EQ((u64)0x0000000FFFFC4001, get_params_response2.seal_params.encryption_params.coeff_modulus()[1].value());
        ASSERT_EQ((u64)0x0000001FFFFE0001, get_params_response2.seal_params.encryption_params.coeff_modulus()[2].value());
    }

	TEST_F(ChannelTests, SendPreprocessResponseTest)
	{
		thread serverth([this]
			{
				shared_ptr<SenderOperation> sender_op;
				server_.receive(sender_op, /* wait_for_message */ true);
				ASSERT_EQ(SOP_preprocess, sender_op->type);

				vector<u8> buffer = { 10, 9, 8, 7, 6 };
				server_.send_preprocess_response(sender_op->client_id, buffer);
			});

		// This buffer will actually be ignored
		vector<u8> buff = { 1 };
		client_.send_preprocess(buff);

		SenderResponsePreprocess preprocess_response;
		client_.receive(preprocess_response);

		ASSERT_EQ((size_t)5, preprocess_response.buffer.size());
		ASSERT_EQ((u8)10, preprocess_response.buffer[0]);
		ASSERT_EQ((u8)9, preprocess_response.buffer[1]);
		ASSERT_EQ((u8)8, preprocess_response.buffer[2]);
		ASSERT_EQ((u8)7, preprocess_response.buffer[3]);
		ASSERT_EQ((u8)6, preprocess_response.buffer[4]);

		serverth.join();
	}

	TEST_F(ChannelTests, SendQueryResponseTest)
	{
		thread serverth([this]
			{
				shared_ptr<SenderOperation> sender_op;
				server_.receive(sender_op, /* wait_for_message */ true);
				ASSERT_EQ(SOP_query, sender_op->type);

				vector<ResultPackage> result(4);

				result[0] = ResultPackage{ 1, 2, "hello", "world" };
				result[1] = ResultPackage{ 3, 4, "one", "two" };
				result[2] = ResultPackage{ 11, 10, "", "non empty" };
				result[3] = ResultPackage{ 15, 20, "data", "" };

				server_.send_query_response(sender_op->client_id, 4);
				server_.send(sender_op->client_id, result[0]);
				server_.send(sender_op->client_id, result[1]);
				server_.send(sender_op->client_id, result[2]);
				server_.send(sender_op->client_id, result[3]);
			});

		EncryptionParameters enc_params(scheme_type::BFV);
		enc_params.set_plain_modulus(64ul);
		enc_params.set_poly_modulus_degree(1024);
		enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
		shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
		KeyGenerator key_gen(context);

		PublicKey pubkey = key_gen.public_key();
		RelinKeys relinkeys = key_gen.relin_keys();

		map<u64, vector<SeededCiphertext>> querydata;
        seed128 relin_keys_seed;

		// Send empty info, it is ignored
		client_.send_query(relinkeys, querydata, relin_keys_seed);

		SenderResponseQuery query_response;
		client_.receive(query_response);

		ASSERT_EQ((size_t)4, query_response.package_count);

		ResultPackage pkg;
		client_.receive(pkg);

		ASSERT_EQ(1, pkg.split_idx);
		ASSERT_EQ(2, pkg.batch_idx);
		ASSERT_TRUE(pkg.data == "hello");
		ASSERT_TRUE(pkg.label_data == "world");

		client_.receive(pkg);

		ASSERT_EQ(3, pkg.split_idx);
		ASSERT_EQ(4, pkg.batch_idx);
		ASSERT_TRUE(pkg.data == "one");
		ASSERT_TRUE(pkg.label_data == "two");

		client_.receive(pkg);

		ASSERT_EQ(11, pkg.split_idx);
		ASSERT_EQ(10, pkg.batch_idx);
		ASSERT_TRUE(pkg.data == "");
		ASSERT_TRUE(pkg.label_data == "non empty");

		client_.receive(pkg);

		ASSERT_EQ(15, pkg.split_idx);
		ASSERT_EQ(20, pkg.batch_idx);
		ASSERT_TRUE(pkg.data == "data");
		ASSERT_TRUE(pkg.label_data == "");

		serverth.join();
	}

	TEST_F(ChannelTests, MultipleClientsTest)
	{
		atomic<bool> finished = false;

		thread serverth([this, &finished]
			{
				SenderChannel sender;

				sender.bind("tcp://*:5552");

				while (!finished)
				{
					shared_ptr<SenderOperation> sender_op;
					if (!sender.receive(sender_op))
					{
						this_thread::sleep_for(50ms);
						continue;
					}

					ASSERT_EQ(SOP_preprocess, sender_op->type);

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
					ReceiverChannel recv;

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

						ASSERT_EQ((size_t)3, preproc.buffer.size());
						ASSERT_EQ((u8)(a * b), preproc.buffer[2]);
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

	TEST_F(ChannelTests, SendResultPackageTest)
	{
		thread serverth([this]
			{
				shared_ptr<SenderOperation> sender_op;
				server_.receive(sender_op, /* wait_for_message */ true);
				ASSERT_EQ(SOP_get_parameters, sender_op->type);

				ResultPackage pkg;
				pkg.split_idx = 1;
				pkg.batch_idx = 2;
				pkg.data = "This is data";
				pkg.label_data = "Not label data";

				server_.send(sender_op->client_id, pkg);

				ResultPackage pkg2;
				pkg2.split_idx = 3;
				pkg2.batch_idx = 4;
				pkg2.data = "small data";
				pkg2.label_data = "";

				server_.send(sender_op->client_id, pkg2);
			});

		client_.send_get_parameters();

		ResultPackage result;
		client_.receive(result);

		ASSERT_EQ(1, result.split_idx);
		ASSERT_EQ(2, result.batch_idx);
		ASSERT_TRUE(result.data == "This is data");
		ASSERT_TRUE(result.label_data == "Not label data");

		ResultPackage result2;
		client_.receive(result2);

		ASSERT_EQ(3, result2.split_idx);
		ASSERT_EQ(4, result2.batch_idx);
		ASSERT_TRUE(result2.data == "small data");
		ASSERT_TRUE(result2.label_data.empty());

		serverth.join();
	}
}
