// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <cstddef>
#include <atomic>
#include <thread>
#include <utility>
#include <algorithm>

// APSI
#include "apsi/receiver.h"
#include "apsi/network/zmq/network_channel.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
using namespace seal;
using namespace kuku;

namespace APSITests
{
    namespace
    {
        SenderChannel server_;
        ReceiverChannel client_;

        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params)
            {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 512;

                PSIParams::QueryParams query_params;
                query_params.query_powers_count = 3;

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params = make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context)
            {
                context = make_shared<CryptoContext>(get_params()->seal_params());
            }

            return context;
        }
    } // namespace

    class ReceiverTests : public ::testing::Test
    {
    protected:
        ReceiverTests()
        {
            logging::Log::set_console_disabled(true);
            logging::Log::set_log_level(logging::Log::Level::debug);
            logging::Log::set_log_file("out.log");

            if (!server_.is_connected())
            {
                server_.bind("tcp://*:5556");
            }

            if (!client_.is_connected())
            {
                client_.connect("tcp://localhost:5556");
            }
        }

        void start_sender(bool labels = false)
        {
            th_ = thread([this](bool labels) {
                // Run until stopped
                while (!stop_token_)
                {
                    unique_ptr<NetworkSenderOperation> sop;
                    if (!(sop = server_.receive_network_operation(get_context()->seal_context())))
                    {
                        this_thread::sleep_for(50ms);
                        continue;
                    }

                    switch (sop->sop->type())
                    {
                    case SenderOperationType::SOP_PARMS:
                        dispatch_parms(move(sop));
                        break;

                    case SenderOperationType::SOP_OPRF:
                        dispatch_oprf(move(sop));
                        break;

                    case SenderOperationType::SOP_QUERY:
                        dispatch_query(move(sop), labels);
                        break;

                    default:
                        // We should never reach this point
                        throw runtime_error("invalid operation");
                    }
                }
            }, labels);
        }

        void dispatch_parms(unique_ptr<NetworkSenderOperation> sop)
        {
            // Handle parms request by responding with the default parameters
            auto response_parms = make_unique<SenderOperationResponseParms>();
            response_parms->params = make_unique<PSIParams>(*get_params());
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_parms);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_oprf(unique_ptr<NetworkSenderOperation> sop)
        {
            auto sop_oprf = dynamic_cast<SenderOperationOPRF*>(sop->sop.get());

            // Respond with exactly the same data we received 
            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = sop_oprf->data;
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_oprf);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_query(unique_ptr<NetworkSenderOperation> sop, bool labels)
        {
            auto sop_query = dynamic_cast<SenderOperationQuery*>(sop->sop.get());

            // We'll return 1 package
            uint32_t package_count = 1; 

            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            auto response = make_unique<NetworkSenderOperationResponse>();
            response->sop_response = move(response_query);
            response->client_id = sop->client_id;

            server_.send(move(response));

            // Query will send result to client in a stream of ResultPackages
            auto send_nrp = [&](Ciphertext ct, uint32_t bundle_idx) {
                auto rp = make_unique<ResultPackage>();
                rp->bundle_idx = bundle_idx;

                // Add label to result if requested
                if (labels)
                {
                    Ciphertext label_ct = ct;

                    // Every other byte will be 1 and every other 0 due to plain_modulus giving 16-bit encodings per
                    // field element
                    Plaintext label_tweak("1");
                    get_context()->evaluator()->add_plain_inplace(label_ct, label_tweak);
                    rp->label_result.push_back(label_ct);
                }

                // Always add PSI result
                rp->psi_result = move(ct);

                auto nrp = make_unique<NetworkResultPackage>();
                nrp->rp = move(rp);
                nrp->client_id = sop->client_id;
                server_.send(move(nrp));
            };

            KukuTable table(
                get_params()->table_params().table_size,
                0,
                get_params()->table_params().hash_func_count,
                make_zero_item(),
                500,
                make_zero_item());

            auto locs = table.all_locations(make_item(1, 0));
            vector<uint64_t> rp_vec(get_context()->encoder()->slot_count(), 1);
            for (auto loc : locs)
            {
                uint32_t bundle_idx = loc / get_params()->items_per_bundle();
                uint32_t bundle_offset = loc - bundle_idx * get_params()->items_per_bundle();
                fill_n(
                    rp_vec.begin() + bundle_offset * get_params()->item_params().felts_per_item,
                    get_params()->item_params().felts_per_item, 0);
            }

            Plaintext rp_pt;
            get_context()->encoder()->encode(rp_vec, rp_pt);
            Ciphertext rp_ct;
            get_context()->encryptor()->encrypt_symmetric(rp_pt, rp_ct);

            send_nrp(move(rp_ct), 0);
        }

        void stop_sender()
        {
            stop_token_ = true;
            if (th_.joinable())
            {
                th_.join();
            }
        }

        ~ReceiverTests()
        {
            stop_sender();

            // Do not disconnect, as the Constructor / Destructor is called for every test.
            // if (client_.is_connected())
            //	client_.disconnect();

            // if (server_.is_connected())
            //	server_.disconnect();
        }

    private:
        thread th_;

        atomic<bool> stop_token_ = false;
    };

    TEST_F(ReceiverTests, Constructor)
    {
        ASSERT_NO_THROW(auto recv = Receiver(*get_params(), 0));
        ASSERT_NO_THROW(auto recv = Receiver(*get_params(), 1));
        ASSERT_NO_THROW(auto recv = Receiver(*get_params(), 2));
    }

    TEST_F(ReceiverTests, RequestParams)
    {
        start_sender();

        PSIParams params = Receiver::RequestParams(client_);
        ASSERT_EQ(get_params()->to_string(), params.to_string());

        stop_sender();
    }

    TEST_F(ReceiverTests, RequestOPRF)
    {
        start_sender();

        vector<Item> items;
        Receiver recv(*get_params());
        auto hashed_items = recv.request_oprf(items, client_);
        ASSERT_TRUE(hashed_items.empty());

        // A single item
        items.push_back(make_item(0, 0));
        hashed_items = recv.request_oprf(items, client_);
        ASSERT_EQ(1, hashed_items.size());
        ASSERT_NE(hashed_items[0][0], items[0][0]);
        ASSERT_NE(hashed_items[0][1], items[0][1]);

        // Same item repeating
        items.push_back(make_item(0, 0));
        hashed_items = recv.request_oprf(items, client_);
        ASSERT_EQ(2, hashed_items.size());
        ASSERT_EQ(hashed_items[0][0], hashed_items[1][0]);
        ASSERT_EQ(hashed_items[0][1], hashed_items[1][1]);

        // Two different items
        items[1][0] = 1;
        hashed_items = recv.request_oprf(items, client_);
        ASSERT_EQ(2, hashed_items.size());
        ASSERT_NE(hashed_items[0][0], hashed_items[1][0]);
        ASSERT_NE(hashed_items[0][1], hashed_items[1][1]);

        stop_sender();
    }

    TEST_F(ReceiverTests, SingleThread)
    {
        start_sender();

        Receiver recv(*get_params(), 1);

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.crypto_context()->secret_key());

        // Empty query; empty response
        vector<HashedItem> items;
        auto query = recv.create_query(items);
        auto result = recv.request_query(move(query), client_);

        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.push_back(HashedItem{make_zero_item()});
        ASSERT_THROW(query = recv.create_query(items), invalid_argument);

        // Query a single non-empty item
        items[0][0] = 1;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query a single non-empty item
        items[0][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.push_back(HashedItem{make_zero_item()});
        items[0][0] = 1;
        items[1][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[1].found);
        ASSERT_FALSE(result[0].label);
        ASSERT_FALSE(result[1].label);

        stop_sender();
    }

    TEST_F(ReceiverTests, MultiThread)
    {
        start_sender();

        Receiver recv(*get_params(), 2);

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.crypto_context()->secret_key());

        // Empty query; empty response
        vector<HashedItem> items;
        auto query = recv.create_query(items);
        auto result = recv.request_query(move(query), client_);
        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.push_back(HashedItem{make_zero_item()});
        ASSERT_THROW(query = recv.create_query(items), invalid_argument);

        // Query a single non-empty item
        items[0][0] = 1;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query a single non-empty item
        items[0][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.push_back(HashedItem{make_zero_item()});
        items[0][0] = 1;
        items[1][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[1].found);
        ASSERT_FALSE(result[0].label);
        ASSERT_FALSE(result[1].label);

        stop_sender();
    }

    TEST_F(ReceiverTests, SingleThreadLabels)
    {
        start_sender(/* labels */ true);

        Receiver recv(*get_params(), 1);

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.crypto_context()->secret_key());
        get_context()->set_evaluator();

        // Empty query; empty response
        vector<HashedItem> items;
        auto query = recv.create_query(items);
        auto result = recv.request_query(move(query), client_);
        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.push_back(HashedItem{make_zero_item()});
        ASSERT_THROW(query = recv.create_query(items), invalid_argument);

        // Query a single non-empty item
        items[0][0] = 1;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_TRUE(result[0].label);

        auto label = result[0].label.get_as<uint16_t>();
        all_of(label.begin(), label.end(), [](auto a) { return a == 1; });

        // Query a single non-empty item
        items[0][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.push_back(HashedItem{make_zero_item()});
        items[0][0] = 1;
        items[1][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_TRUE(result[0].label);
        ASSERT_FALSE(result[1].found);
        ASSERT_FALSE(result[1].label);

        label = result[0].label.get_as<uint16_t>();
        all_of(label.begin(), label.end(), [](auto a) { return a == 1; });

        stop_sender();
    }

    TEST_F(ReceiverTests, MultiThreadLabels)
    {
        start_sender(/* labels */ true);

        Receiver recv(*get_params(), 2);

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.crypto_context()->secret_key());
        get_context()->set_evaluator();

        // Empty query; empty response
        vector<HashedItem> items;
        auto query = recv.create_query(items);
        auto result = recv.request_query(move(query), client_);
        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.push_back(HashedItem{make_zero_item()});
        ASSERT_THROW(query = recv.create_query(items), invalid_argument);

        // Query a single non-empty item
        items[0][0] = 1;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_TRUE(result[0].label);

        auto label = result[0].label.get_as<uint16_t>();
        all_of(label.begin(), label.end(), [](auto a) { return a == 1; });

        // Query a single non-empty item
        items[0][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.push_back(HashedItem{make_zero_item()});
        items[0][0] = 1;
        items[1][0] = 2;
        query = recv.create_query(items);
        result = recv.request_query(move(query), client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[1].found);
        ASSERT_TRUE(result[0].label);
        ASSERT_FALSE(result[1].label);

        label = result[0].label.get_as<uint16_t>();
        all_of(label.begin(), label.end(), [](auto a) { return a == 1; });

        stop_sender();
    }
}