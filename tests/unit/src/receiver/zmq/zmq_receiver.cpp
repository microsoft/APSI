// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>
#include <thread>
#include <type_traits>
#include <utility>

// APSI
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/receiver.h"
#include "apsi/thread_pool_mgr.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
using namespace apsi::util;
using namespace seal;
using namespace kuku;

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
            }

            return context;
        }
    } // namespace

    class ReceiverTests : public ::testing::Test {
    protected:
        ReceiverTests()
        {
            if (!server_.is_connected()) {
                server_.bind("tcp://*:5556");
            }

            if (!client_.is_connected()) {
                client_.connect("tcp://localhost:5556");
            }
        }

        void start_sender(bool labels = false)
        {
            th_ = thread([this, labels]() {
                // Run until stopped
                while (!stop_token_) {
                    unique_ptr<ZMQSenderOperation> sop;
                    if (!(sop = server_.receive_network_operation(get_context()->seal_context()))) {
                        this_thread::sleep_for(50ms);
                        continue;
                    }

                    switch (sop->sop->type()) {
                    case SenderOperationType::sop_parms:
                        dispatch_parms(move(sop));
                        break;

                    case SenderOperationType::sop_oprf:
                        dispatch_oprf(move(sop));
                        break;

                    case SenderOperationType::sop_query:
                        dispatch_query(move(sop), labels);
                        break;

                    default:
                        // We should never reach this point
                        throw runtime_error("invalid operation");
                    }
                }
            });
        }

        void dispatch_parms(unique_ptr<ZMQSenderOperation> sop)
        {
            // Handle parms request by responding with the default parameters
            auto response_parms = make_unique<SenderOperationResponseParms>();
            response_parms->params = make_unique<PSIParams>(*get_params());
            auto response = make_unique<ZMQSenderOperationResponse>();
            response->sop_response = move(response_parms);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_oprf(unique_ptr<ZMQSenderOperation> sop)
        {
            auto sop_oprf = dynamic_cast<SenderOperationOPRF *>(sop->sop.get());

            // Respond with exactly the same data we received
            auto response_oprf = make_unique<SenderOperationResponseOPRF>();
            response_oprf->data = sop_oprf->data;
            auto response = make_unique<ZMQSenderOperationResponse>();
            response->sop_response = move(response_oprf);
            response->client_id = move(sop->client_id);

            server_.send(move(response));
        }

        void dispatch_query(unique_ptr<ZMQSenderOperation> sop, bool labels)
        {
            // We'll return 1 package
            uint32_t package_count = 1;

            auto response_query = make_unique<SenderOperationResponseQuery>();
            response_query->package_count = package_count;
            auto response = make_unique<ZMQSenderOperationResponse>();
            response->sop_response = move(response_query);
            response->client_id = sop->client_id;

            server_.send(move(response));

            // Query will send result to client in a stream of ResultPackages
            auto send_nrp = [&](Ciphertext ct, uint32_t bundle_idx) {
                auto rp = make_unique<ResultPackage>();
                rp->bundle_idx = bundle_idx;

                // Add label to result if requested
                if (labels) {
                    rp->label_byte_count = 1;
                    Ciphertext label_ct = ct;

                    // Every other byte will be 1 and every other 0 due to plain_modulus giving
                    // 16-bit encodings per field element
                    Plaintext label_tweak("1");
                    get_context()->evaluator()->add_plain_inplace(label_ct, label_tweak);
                    rp->label_result.push_back(label_ct);
                }

                // Always add PSI result
                rp->psi_result = move(ct);

                auto nrp = make_unique<ZMQResultPackage>();
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
            using rp_vec_diff_type = typename decay_t<decltype(rp_vec)>::difference_type;
            for (auto loc : locs) {
                uint32_t bundle_idx = loc / get_params()->items_per_bundle();
                uint32_t bundle_offset = loc - bundle_idx * get_params()->items_per_bundle();
                uint32_t offset = bundle_offset * get_params()->item_params().felts_per_item;
                fill_n(
                    rp_vec.begin() + static_cast<rp_vec_diff_type>(offset),
                    get_params()->item_params().felts_per_item,
                    0);
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
            if (th_.joinable()) {
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

        atomic<bool> stop_token_{ false };
    };

    TEST_F(ReceiverTests, Constructor)
    {
        ASSERT_NO_THROW(auto recv = Receiver(*get_params()));
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
        auto hashed_items = Receiver::RequestOPRF(items, client_);
        ASSERT_TRUE(hashed_items.first.empty());
        ASSERT_TRUE(hashed_items.second.empty());

        // A single item
        items.emplace_back(0, 0);
        hashed_items = Receiver::RequestOPRF(items, client_);
        ASSERT_EQ(1, hashed_items.first.size());
        ASSERT_EQ(1, hashed_items.second.size());
        ASSERT_NE(hashed_items.first[0].value(), items[0].value());

        // Same item repeating
        items.emplace_back(0, 0);
        hashed_items = Receiver::RequestOPRF(items, client_);
        ASSERT_EQ(2, hashed_items.first.size());
        ASSERT_EQ(2, hashed_items.second.size());
        ASSERT_EQ(hashed_items.first[0].value(), hashed_items.first[1].value());
        ASSERT_EQ(hashed_items.second[0], hashed_items.second[1]);

        // Two different items
        items[1].value()[0] = 1;
        hashed_items = Receiver::RequestOPRF(items, client_);
        ASSERT_EQ(2, hashed_items.first.size());
        ASSERT_EQ(2, hashed_items.second.size());
        ASSERT_NE(hashed_items.first[0].value(), hashed_items.first[1].value());
        ASSERT_NE(hashed_items.second[0], hashed_items.second[1]);
        ASSERT_NE(hashed_items.first[0].value(), hashed_items.first[1].value());
        ASSERT_NE(hashed_items.second[0], hashed_items.second[1]);

        stop_sender();
    }

    TEST_F(ReceiverTests, SingleThread)
    {
        ThreadPoolMgr::SetThreadCount(1);

        start_sender();

        Receiver recv(*get_params());

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.get_crypto_context().secret_key());

        // Empty query; empty response
        vector<HashedItem> items;
        vector<LabelKey> label_keys;
        auto result = recv.request_query(items, label_keys, client_);

        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.emplace_back(0, 0);
        label_keys.push_back(LabelKey{});
        ASSERT_THROW(recv.request_query(items, label_keys, client_), invalid_argument);

        // Query a single non-empty item
        items[0].value()[0] = 1;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query a single non-empty item
        items[0].value()[0] = 2;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.emplace_back(0, 0);
        label_keys.push_back(LabelKey{});
        items[0].value()[0] = 1;
        items[1].value()[0] = 2;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[1].found);
        ASSERT_FALSE(result[0].label);
        ASSERT_FALSE(result[1].label);

        stop_sender();
    }

    TEST_F(ReceiverTests, MultiThread)
    {
        ThreadPoolMgr::SetThreadCount(2);

        start_sender();

        Receiver recv(*get_params());

        // Give the sender the secret key so they can fake responses
        get_context()->set_secret(*recv.get_crypto_context().secret_key());

        // Empty query; empty response
        vector<HashedItem> items;
        vector<LabelKey> label_keys;
        auto result = recv.request_query(items, label_keys, client_);
        ASSERT_TRUE(result.empty());

        // Cannot query the empty item
        items.emplace_back(0, 0);
        label_keys.push_back(LabelKey{});
        ASSERT_THROW(recv.request_query(items, label_keys, client_), invalid_argument);

        // Query a single non-empty item
        items[0].value()[0] = 1;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(1, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query a single non-empty item
        items[0].value()[0] = 2;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(1, result.size());
        ASSERT_FALSE(result[0].found);
        ASSERT_FALSE(result[0].label);

        // Query two items
        items.emplace_back(0, 0);
        label_keys.push_back(LabelKey{});
        items[0].value()[0] = 1;
        items[1].value()[0] = 2;
        result = recv.request_query(items, label_keys, client_);
        ASSERT_EQ(2, result.size());
        ASSERT_TRUE(result[0].found);
        ASSERT_FALSE(result[1].found);
        ASSERT_FALSE(result[0].label);
        ASSERT_FALSE(result[1].label);

        stop_sender();
    }
} // namespace APSITests
