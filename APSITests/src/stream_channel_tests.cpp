// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "apsi/network/stream_channel.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"
#include "seal/relinkeys.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace seal;

namespace APSITests
{
    class StreamChannelTests : public ::testing::Test
    {
    protected:
        StreamChannelTests()
        {
        }

        ~StreamChannelTests()
        {
        }
    };

    TEST_F(StreamChannelTests, SendGetParametersTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        receiverchannel.send_get_parameters();
        stream1.seekp(0);

        shared_ptr<SenderOperation> sender_op;
        senderchannel.receive(sender_op);

        ASSERT_EQ(SOP_get_parameters, sender_op->type);
    }

    TEST_F(StreamChannelTests, SendGetParameterResponseTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        PSIParams::PSIConfParams psiconf_params{ 60, true, false, false, 12345, 90, 45, 128 };
        PSIParams::TableParams table_params{ 10, 1, 2, 35, 40 };
        PSIParams::CuckooParams cuckoo_params{ 3, 2, 1 };
        PSIParams::ExFieldParams exfield_params{ 678910, 8 };
        PSIParams::SEALParams seal_params;
        seal_params.decomposition_bit_count = 30;
        seal_params.max_supported_degree = 20;
        seal_params.encryption_params.set_plain_modulus(5119);
        seal_params.encryption_params.set_poly_modulus_degree(4096);
        vector<SmallModulus> coeff_modulus = CoeffModulus::BFVDefault(seal_params.encryption_params.poly_modulus_degree());
        seal_params.encryption_params.set_coeff_modulus(coeff_modulus);

        PSIParams params(psiconf_params, table_params, cuckoo_params, seal_params, exfield_params);

        vector<u8> client_id;
        senderchannel.send_get_parameters_response(client_id, params);
        stream2.seekp(0);

        SenderResponseGetParameters gpr;
        receiverchannel.receive(gpr);

        ASSERT_EQ(60, gpr.psiconf_params.item_bit_count);
        ASSERT_EQ(true, gpr.psiconf_params.use_oprf);
        ASSERT_EQ(false, gpr.psiconf_params.use_labels);
        ASSERT_EQ(false, gpr.psiconf_params.use_fast_membership);
        ASSERT_EQ((u64)12345, gpr.psiconf_params.sender_size);
        ASSERT_EQ(90, gpr.psiconf_params.item_bit_length_used_after_oprf);
        ASSERT_EQ(45, gpr.psiconf_params.num_chunks);
        ASSERT_EQ(128, gpr.psiconf_params.sender_bin_size);

        ASSERT_EQ(10, gpr.table_params.log_table_size);
        ASSERT_EQ(1, gpr.table_params.window_size);
        ASSERT_EQ(2, gpr.table_params.split_count);
        ASSERT_EQ(35, gpr.table_params.split_size);
        ASSERT_EQ(40, gpr.table_params.binning_sec_level);

        ASSERT_EQ(3, gpr.cuckoo_params.hash_func_count);
        ASSERT_EQ(2, gpr.cuckoo_params.hash_func_seed);
        ASSERT_EQ(1, gpr.cuckoo_params.max_probe);

        ASSERT_EQ((u64)678910, gpr.exfield_params.characteristic);
        ASSERT_EQ(8, gpr.exfield_params.degree);

        ASSERT_EQ(30, gpr.seal_params.decomposition_bit_count);
        ASSERT_EQ(20, gpr.seal_params.max_supported_degree);
        ASSERT_EQ((u64)5119, gpr.seal_params.encryption_params.plain_modulus().value());
        ASSERT_EQ((size_t)4096, gpr.seal_params.encryption_params.poly_modulus_degree());
        ASSERT_EQ((size_t)3, gpr.seal_params.encryption_params.coeff_modulus().size());
    }

    TEST_F(StreamChannelTests, SendPreprocessTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        vector<u8> items = { 10, 20, 30, 40, 50 };

        receiverchannel.send_preprocess(items);
        stream1.seekp(0);

        shared_ptr<SenderOperation> sender_op;
        senderchannel.receive(sender_op);

        ASSERT_EQ(SOP_preprocess, sender_op->type);

        shared_ptr<SenderOperationPreprocess> preprocess_op = dynamic_pointer_cast<SenderOperationPreprocess>(sender_op);
        ASSERT_TRUE(nullptr != preprocess_op);

        ASSERT_EQ((size_t)5, preprocess_op->buffer.size());
        ASSERT_EQ(10, preprocess_op->buffer[0]);
        ASSERT_EQ(20, preprocess_op->buffer[1]);
        ASSERT_EQ(30, preprocess_op->buffer[2]);
        ASSERT_EQ(40, preprocess_op->buffer[3]);
        ASSERT_EQ(50, preprocess_op->buffer[4]);
    }

    TEST_F(StreamChannelTests, SendPreprocessResponseTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        vector<u8> buffer{ 100, 95, 80, 75, 60, 55, 40, 35, 20, 15, 10, 4, 3, 2 , 1 };

        vector<u8> client_id;
        senderchannel.send_preprocess_response(client_id, buffer);
        stream2.seekp(0);

        SenderResponsePreprocess pr;
        receiverchannel.receive(pr);

        ASSERT_EQ((size_t)15, pr.buffer.size());
        ASSERT_EQ((u8)100, pr.buffer[0]);
        ASSERT_EQ((u8)95, pr.buffer[1]);
        ASSERT_EQ((u8)80, pr.buffer[2]);
        ASSERT_EQ((u8)75, pr.buffer[3]);
        ASSERT_EQ((u8)60, pr.buffer[4]);
        ASSERT_EQ((u8)55, pr.buffer[5]);
        ASSERT_EQ((u8)40, pr.buffer[6]);
        ASSERT_EQ((u8)35, pr.buffer[7]);
        ASSERT_EQ((u8)20, pr.buffer[8]);
        ASSERT_EQ((u8)15, pr.buffer[9]);
        ASSERT_EQ((u8)10, pr.buffer[10]);
        ASSERT_EQ((u8)4, pr.buffer[11]);
        ASSERT_EQ((u8)3, pr.buffer[12]);
        ASSERT_EQ((u8)2, pr.buffer[13]);
        ASSERT_EQ((u8)1, pr.buffer[14]);
    }

    TEST_F(StreamChannelTests, SendQueryTest)
    {
        stringstream stream1;
        stringstream stream2;
        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        EncryptionParameters enc_params(scheme_type::BFV);
        enc_params.set_plain_modulus(64ul);
        enc_params.set_poly_modulus_degree(1024);
        enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
        shared_ptr<SEALContext> context = SEALContext::Create(enc_params);
        KeyGenerator key_gen(context);

        seed128 seeds = { 1, 2 };
        RelinKeys relin_keys = key_gen.relin_keys();

        map<u64, vector<SeededCiphertext>> query;

        vector<SeededCiphertext> vec;
        seeds = { 2, 3 };
        vec.push_back(SeededCiphertext(seeds, Ciphertext()));

        query.insert_or_assign(5, vec);

        vec.clear();
        seeds = { 4, 5 };
        vec.push_back(SeededCiphertext(seeds, Ciphertext()));
        seeds = { 5, 6 };
        vec.push_back(SeededCiphertext(seeds, Ciphertext()));

        query.insert_or_assign(10, vec);

        seeds = { 6, 7 };
        receiverchannel.send_query(relin_keys, query, seeds);
        stream1.seekp(0);

        shared_ptr<SenderOperation> sender_op;
        senderchannel.receive(sender_op);

        ASSERT_EQ(SOP_query, sender_op->type);

        shared_ptr<SenderOperationQuery> query_op = dynamic_pointer_cast<SenderOperationQuery>(sender_op);
        ASSERT_TRUE(nullptr != query_op);

        ASSERT_TRUE(query_op->relin_keys.length() > 0);
        ASSERT_EQ((size_t)2, query_op->query.size());
        ASSERT_EQ((size_t)1, query_op->query.at(5).size());
        ASSERT_EQ((u64)2, query_op->query.at(5).at(0).first.first);
        ASSERT_EQ((u64)3, query_op->query.at(5).at(0).first.second);
        ASSERT_EQ((size_t)2, query_op->query.at(10).size());
        ASSERT_EQ((u64)4, query_op->query.at(10).at(0).first.first);
        ASSERT_EQ((u64)5, query_op->query.at(10).at(0).first.second);
        ASSERT_EQ((u64)5, query_op->query.at(10).at(1).first.first);
        ASSERT_EQ((u64)6, query_op->query.at(10).at(1).first.second);
        ASSERT_EQ((u64)6, query_op->relin_keys_seeds.first);
        ASSERT_EQ((u64)7, query_op->relin_keys_seeds.second);
    }

    TEST_F(StreamChannelTests, SendQueryResponseTest)
    {
        stringstream stream1;
        stringstream stream2;
        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        vector<u8> client_id;
        senderchannel.send_query_response(client_id, 50);
        stream2.seekp(0);

        SenderResponseQuery rq;
        receiverchannel.receive(rq);

        ASSERT_EQ((u64)50, rq.package_count);
    }

    TEST_F(StreamChannelTests, SendPackageTest)
    {
        stringstream stream1;
        stringstream stream2;
        StreamChannel senderchannel(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel receiverchannel(/* istream */ stream2, /* ostream */ stream1);

        ResultPackage pkg;

        pkg.batch_idx = 1;
        pkg.split_idx = 2;
        pkg.data = "One";
        pkg.label_data = "Two";

        vector<u8> client_id;
        senderchannel.send(client_id, pkg);

        pkg.batch_idx = 3;
        pkg.split_idx = 4;
        pkg.data = "Three";
        pkg.label_data = "Four";

        senderchannel.send(client_id, pkg);

        pkg.batch_idx = 5;
        pkg.split_idx = 6;
        pkg.data = "Five";
        pkg.label_data = "Six";

        senderchannel.send(client_id, pkg);
        stream2.seekp(0);

        ResultPackage received;
        receiverchannel.receive(received);

        ASSERT_EQ(1, received.batch_idx);
        ASSERT_EQ(2, received.split_idx);
        ASSERT_TRUE(received.data == "One");
        ASSERT_TRUE(received.label_data == "Two");

        receiverchannel.receive(received);

        ASSERT_EQ(3, received.batch_idx);
        ASSERT_EQ(4, received.split_idx);
        ASSERT_TRUE(received.data == "Three");
        ASSERT_TRUE(received.label_data == "Four");

        receiverchannel.receive(received);

        ASSERT_EQ(5, received.batch_idx);
        ASSERT_EQ(6, received.split_idx);
        ASSERT_TRUE(received.data == "Five");
        ASSERT_TRUE(received.label_data == "Six");
    }
}
