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
#include "apsi/network/zmq/zmq_channel.h"
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
        ZMQSenderChannel server_;
        ZMQReceiverChannel client_;

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
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
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
                context->set_evaluator(move(rlk));
            }

            return context;
        }
    } // namespace

    class ZMQChannelTests : public ::testing::Test {
    protected:
        ZMQChannelTests()
        {
            if (!server_.is_connected()) {
                server_.bind("tcp://*:5555");
            }

            if (!client_.is_connected()) {
                client_.connect("tcp://localhost:5555");
            }

            // Set up the context ahead of time
            (void)get_context();
        }

        ~ZMQChannelTests()
        {
            // Do not disconnect, as the Constructor / Destructor is called for every test.
            // if (client_.is_connected())
            //	client_.disconnect();

            // if (server_.is_connected())
            //	server_.disconnect();
        }
    };

    TEST_F(ZMQChannelTests, ThrowWithoutConnectTest)
    {
        // ZMQSenderChannel and ZMQReceiverChannel are identical for the purposes of this test
        ZMQSenderChannel mychannel;

        // Receives
        ASSERT_THROW(mychannel.receive_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_network_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_response(), runtime_error);
        ASSERT_THROW(mychannel.receive_result(nullptr), runtime_error);

        // Sends
        ASSERT_THROW(mychannel.send(make_unique<ResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<ZMQResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationResponseParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<ZMQSenderOperationResponse>()), runtime_error);
    }

    TEST_F(ZMQChannelTests, ClientServerFullSession)
    {
        ZMQSenderChannel svr;
        ZMQReceiverChannel clt;

        svr.bind("tcp://*:5554");
        clt.connect("tcp://localhost:5554");

        thread clientth([&clt] {
            this_thread::sleep_for(50ms);

            auto sop_parms = make_unique<SenderOperationParms>();
            unique_ptr<SenderOperation> sop = make_unique<SenderOperationParms>();

            // Send a Parms operation
            clt.send(move(sop));

            // Fill a data buffer
            vector<unsigned char> oprf_data(256);
            for (size_t i = 0; i < oprf_data.size(); i++) {
                oprf_data[i] = static_cast<unsigned char>(i);
            }

            auto sop_oprf = make_unique<SenderOperationOPRF>();
            sop_oprf->data = oprf_data;
            sop = move(sop_oprf);

            // Send an OPRF operation with some dummy data
            clt.send(move(sop));

            auto sop_query = make_unique<SenderOperationQuery>();
            auto relin_keys = get_context()->relin_keys();
            sop_query->relin_keys = *relin_keys;
            sop_query->data[0].push_back(get_context()->encryptor()->encrypt_zero_symmetric());
            sop_query->data[123].push_back(get_context()->encryptor()->encrypt_zero_symmetric());
            sop = move(sop_query);

            // Send a query operation with some dummy data
            clt.send(move(sop));

            // Next, try receiving an OPRF response; this is incorrect so should return nullptr
            ASSERT_EQ(nullptr, clt.receive_response(SenderOperationType::sop_oprf));

            // Receive correctly the parms response
            auto rsop = clt.receive_response(SenderOperationType::sop_parms);
            unique_ptr<SenderOperationResponseParms> rsop_parms;
            rsop_parms.reset(dynamic_cast<SenderOperationResponseParms *>(rsop.release()));

            // We received valid parameters
            ASSERT_EQ(get_params()->item_bit_count(), rsop_parms->params->item_bit_count());

            // Receive an OPRF response
            rsop = clt.receive_response(SenderOperationType::sop_oprf);
            unique_ptr<SenderOperationResponseOPRF> rsop_oprf;
            rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(rsop.release()));

            ASSERT_EQ(256, rsop_oprf->data.size());
            for (size_t i = 0; i < rsop_oprf->data.size(); i++) {
                ASSERT_EQ(static_cast<char>(rsop_oprf->data[i]), static_cast<char>(i));
            }

            // Receive a query response
            rsop = clt.receive_response(SenderOperationType::sop_query);
            unique_ptr<SenderOperationResponseQuery> rsop_query;
            rsop_query.reset(dynamic_cast<SenderOperationResponseQuery *>(rsop.release()));

            ASSERT_EQ(2, rsop_query->package_count);

            // Receive two packages
            auto rp = clt.receive_result(get_context()->seal_context());
            ASSERT_EQ(0, rp->bundle_idx);
            ASSERT_EQ(0, rp->label_byte_count);
            ASSERT_EQ(0, rp->nonce_byte_count);
            ASSERT_TRUE(rp->label_result.empty());

            rp = clt.receive_result(get_context()->seal_context());
            ASSERT_EQ(123, rp->bundle_idx);
            ASSERT_EQ(80, rp->label_byte_count);
            ASSERT_EQ(4, rp->nonce_byte_count);
            ASSERT_EQ(1, rp->label_result.size());
        });

        // Receive a parms operation
        auto sop_parms = make_unique<SenderOperationParms>();

        // It's important to receive this as a SenderNetworkOperation, otherwise we can't get the
        // client_id for ZeroMQ internal routing.
        auto nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_parms, nsop->sop->type());
        ASSERT_FALSE(nsop->client_id.empty());
        auto client_id = nsop->client_id;

        // Receive an OPRF operation
        nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_oprf, nsop->sop->type());
        ASSERT_EQ(client_id, nsop->client_id);
        unique_ptr<SenderOperationOPRF> sop_oprf;
        sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(nsop->sop.release()));

        ASSERT_EQ(256, sop_oprf->data.size());
        for (size_t i = 0; i < sop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(sop_oprf->data[i]), static_cast<char>(i));
        }

        // Receive a query operation
        nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_query, nsop->sop->type());
        ASSERT_EQ(client_id, nsop->client_id);
        unique_ptr<SenderOperationQuery> sop_query;
        sop_query.reset(dynamic_cast<SenderOperationQuery *>(nsop->sop.release()));

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

        // Create a parms response
        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());

        // Actually we need a ZMQSenderOperationResponse for ZeroMQ; we'll need to use the correct
        // client_id here.
        auto nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = move(rsop_parms);

        // Try sending the parameters; the receiver is incorrectly expecting an OPRF response so it
        // will fail to receive this package. We'll have to send it twice so that on the second time
        // it gets the response correctly.
        svr.send(move(nrsop));

        // Send again so receiver actually gets it
        rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = move(rsop_parms);
        svr.send(move(nrsop));

        // Create an OPRF response and response with the same data we received
        auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
        rsop_oprf->data = sop_oprf->data;
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = move(rsop_oprf);
        svr.send(move(nrsop));

        // Create a query response; we will return two packages
        auto rsop_query = make_unique<SenderOperationResponseQuery>();
        rsop_query->package_count = 2;
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = move(rsop_query);
        svr.send(move(nrsop));

        // Finally send two ZMQResultPackages
        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        rp->psi_result = query_ct0;
        auto nrp = make_unique<ZMQResultPackage>();
        nrp->client_id = client_id;
        nrp->rp = move(rp);
        svr.send(move(nrp));

        rp = make_unique<ResultPackage>();
        rp->bundle_idx = 123;
        rp->label_byte_count = 80;
        rp->nonce_byte_count = 4;
        rp->psi_result = query_ct123;
        rp->label_result.push_back(query_ct123);
        nrp = make_unique<ZMQResultPackage>();
        nrp->client_id = client_id;
        nrp->rp = move(rp);
        svr.send(move(nrp));

        clientth.join();
    }

    TEST_F(ZMQChannelTests, MultipleClients)
    {
        atomic<bool> finished{ false };

        thread serverth([&finished] {
            ZMQSenderChannel sender;

            sender.bind("tcp://*:5552");

            while (!finished) {
                unique_ptr<ZMQSenderOperation> sop;
                if (!(sop = sender.receive_network_operation(get_context()->seal_context()))) {
                    this_thread::sleep_for(50ms);
                    continue;
                }

                ASSERT_EQ(SenderOperationType::sop_oprf, sop->sop->type());
                unique_ptr<SenderOperationOPRF> sop_oprf;
                sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(sop->sop.release()));
                auto client_id = sop->client_id;

                // Return the same data we received
                auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
                rsop_oprf->data = sop_oprf->data;
                auto sopr = make_unique<ZMQSenderOperationResponse>();
                sopr->client_id = client_id;
                sopr->sop_response = move(rsop_oprf);

                // Send
                sender.send(move(sopr));
            }
        });

        vector<thread> clients(5);
        for (size_t i = 0; i < clients.size(); i++) {
            clients[i] = thread([]() {
                ZMQReceiverChannel recv;

                recv.connect("tcp://localhost:5552");

                for (uint32_t k = 0; k < 5; k++) {
                    vector<unsigned char> oprf_data(256);
                    for (size_t j = 0; j < oprf_data.size(); j++) {
                        oprf_data[j] = static_cast<unsigned char>(j);
                    }

                    auto sop_oprf = make_unique<SenderOperationOPRF>();
                    sop_oprf->data = oprf_data;
                    unique_ptr<SenderOperation> sop = move(sop_oprf);
                    recv.send(move(sop));

                    auto sopr = recv.receive_response();
                    ASSERT_NE(nullptr, sopr);
                    unique_ptr<SenderOperationResponseOPRF> rsop_oprf;
                    rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(sopr.release()));

                    // Check that we receive what we sent
                    ASSERT_EQ(256, rsop_oprf->data.size());
                    for (size_t j = 0; j < rsop_oprf->data.size(); j++) {
                        ASSERT_EQ(
                            static_cast<unsigned char>(rsop_oprf->data[j]),
                            static_cast<unsigned char>(j));
                    }
                }
            });
        }

        for (size_t i = 0; i < clients.size(); i++) {
            clients[i].join();
        }

        finished = true;
        serverth.join();
    }
} // namespace APSITests
