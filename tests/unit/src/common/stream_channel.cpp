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
#include "apsi/network/stream_channel.h"
#include "apsi/powers.h"
#include "apsi/util/utils.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 512;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::Create(pmd, { 40, 40 }));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context) {
                context = make_shared<CryptoContext>(*get_params());
                KeyGenerator keygen(*context->seal_context());
                context->set_secret(keygen.secret_key());
                RelinKeys rlk;
                keygen.create_relin_keys(rlk);
                context->set_evaluator(std::move(rlk));
            }

            return context;
        }
    } // namespace

    class StreamChannelTests : public ::testing::Test {
    protected:
        StreamChannelTests()
        {}

        ~StreamChannelTests()
        {}
    };

    TEST_F(StreamChannelTests, SendReceiveParms)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        unique_ptr<SenderOperation> sop = make_unique<SenderOperationParms>();

        // Send a parms operation
        clt.send(std::move(sop));

        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_NE(nullptr, sop);
        ASSERT_EQ(SenderOperationType::sop_parms, sop->type());

        // Create a parms response
        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_parms);
        svr.send(std::move(rsop));

        // Receive the parms response
        rsop = clt.receive_response(SenderOperationType::sop_parms);
        rsop_parms.reset(dynamic_cast<SenderOperationResponseParms *>(rsop.release()));

        // We received valid parameters
        ASSERT_EQ(get_params()->item_bit_count(), rsop_parms->params->item_bit_count());

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }

    TEST_F(StreamChannelTests, SendReceiveOPRFTest)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        // Fill a data buffer
        vector<unsigned char> oprf_data(256);
        for (size_t i = 0; i < oprf_data.size(); i++) {
            oprf_data[i] = static_cast<unsigned char>(i);
        }

        auto sop_oprf = make_unique<SenderOperationOPRF>();
        sop_oprf->data = oprf_data;
        unique_ptr<SenderOperation> sop = std::move(sop_oprf);

        // Send an OPRF operation
        clt.send(std::move(sop));

        // Receive the operation
        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_EQ(SenderOperationType::sop_oprf, sop->type());
        sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(sop.release()));

        // Validate the data
        ASSERT_EQ(256, sop_oprf->data.size());
        for (size_t i = 0; i < sop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(sop_oprf->data[i]), static_cast<char>(i));
        }

        // Create an OPRF response
        auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
        rsop_oprf->data = oprf_data;
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_oprf);
        svr.send(std::move(rsop));

        // Receive the OPRF response
        rsop = clt.receive_response(SenderOperationType::sop_oprf);
        rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(rsop.release()));

        // Validate the data
        ASSERT_EQ(256, rsop_oprf->data.size());
        for (size_t i = 0; i < rsop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(rsop_oprf->data[i]), static_cast<char>(i));
        }

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }

    TEST_F(StreamChannelTests, SendReceiveQuery)
    {
        stringstream stream1;
        stringstream stream2;

        StreamChannel svr(/* istream */ stream1, /* ostream */ stream2);
        StreamChannel clt(/* istream */ stream2, /* ostream */ stream1);

        auto sop_query = make_unique<SenderOperationQuery>();
        sop_query->relin_keys = *get_context()->relin_keys();
        sop_query->data[0].push_back(get_context()->encryptor()->encrypt_zero_symmetric());
        sop_query->data[123].push_back(get_context()->encryptor()->encrypt_zero_symmetric());
        unique_ptr<SenderOperation> sop = std::move(sop_query);

        // Send a query operation
        clt.send(std::move(sop));

        // Receive the operation
        sop = svr.receive_operation(get_context()->seal_context());
        ASSERT_EQ(SenderOperationType::sop_query, sop->type());
        sop_query.reset(dynamic_cast<SenderOperationQuery *>(sop.release()));

        // Are we able to extract the relinearization keys?
        ASSERT_NO_THROW(auto rlk = sop_query->relin_keys.extract_if_local());

        // Check for query ciphertexts
        ASSERT_EQ(2, sop_query->data.size());

        ASSERT_FALSE(sop_query->data.at(0).empty());
        ASSERT_EQ(1, sop_query->data[0].size());
        auto query_ct0 = sop_query->data[0][0].extract_if_local();

        ASSERT_FALSE(sop_query->data.at(123).empty());
        ASSERT_EQ(1, sop_query->data[123].size());
        auto query_ct123 = sop_query->data[123][0].extract_if_local();

        // Create a query response
        auto rsop_query = make_unique<SenderOperationResponseQuery>();
        rsop_query->package_count = 2;
        unique_ptr<SenderOperationResponse> rsop = std::move(rsop_query);
        svr.send(std::move(rsop));

        // Receive the query response
        rsop = clt.receive_response(SenderOperationType::sop_query);
        rsop_query.reset(dynamic_cast<SenderOperationResponseQuery *>(rsop.release()));

        // Validate the data
        ASSERT_EQ(2, rsop_query->package_count);

        // Send two ResultPackages
        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        rp->psi_result = query_ct0;
        svr.send(std::move(rp));

        rp = make_unique<ResultPackage>();
        rp->bundle_idx = 123;
        rp->label_byte_count = 80;
        rp->nonce_byte_count = 4;
        rp->psi_result = query_ct123;
        rp->label_result.push_back(query_ct123);
        svr.send(std::move(rp));

        // Receive two packages
        rp = clt.receive_result(get_context()->seal_context());
        ASSERT_EQ(0, rp->bundle_idx);
        ASSERT_EQ(0, rp->label_byte_count);
        ASSERT_EQ(0, rp->bundle_idx);
        ASSERT_TRUE(rp->label_result.empty());

        rp = clt.receive_result(get_context()->seal_context());
        ASSERT_EQ(123, rp->bundle_idx);
        ASSERT_EQ(80, rp->label_byte_count);
        ASSERT_EQ(4, rp->nonce_byte_count);
        ASSERT_EQ(1, rp->label_result.size());

        ASSERT_EQ(svr.bytes_sent(), clt.bytes_received());
        ASSERT_EQ(svr.bytes_received(), clt.bytes_sent());
    }
} // namespace APSITests
