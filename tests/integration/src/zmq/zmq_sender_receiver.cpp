// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
#include "apsi/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "test_utils.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::util;
using namespace apsi::oprf;
using namespace seal;

namespace APSITests {
    namespace {
        bool verify_unlabeled_results(
            const vector<MatchRecord> &query_result,
            const vector<Item> &query_vec,
            const vector<Item> &int_items)
        {
            // Count matches
            size_t match_count = accumulate(
                query_result.cbegin(), query_result.cend(), size_t(0), [](auto sum, auto &curr) {
                    return sum + curr.found;
                });

            // Check that intersection size is correct
            if (int_items.size() != match_count) {
                std::cerr << "intersection size is not correct" << std::endl;
                return false;
            }

            // Check that every intersection item was actually found
            for (auto &item : int_items) {
                auto where = find(query_vec.begin(), query_vec.end(), item);
                if (query_vec.end() == where) {
                    std::cerr << "Could not find intersection item" << std::endl;
                    return false;
                }

                auto idx = distance(query_vec.begin(), where);
                if (!query_result[idx].found) {
                    std::cerr << "Query result should be found" << std::endl;
                    return false;
                }
            }

            return true;
        }

        bool verify_labeled_results(
            const vector<MatchRecord> &query_result,
            const vector<Item> &query_vec,
            const vector<Item> &int_items,
            const vector<pair<Item, Label>> &all_item_labels)
        {
            verify_unlabeled_results(query_result, query_vec, int_items);

            // Verify that all labels were received for items that were found
            for (auto &result : query_result) {
                if (result.found) {
                    if (!result.label) {
                        std::cerr << "Label does not contain data" << std::endl;
                        return false;
                    }
                }
            }

            // Check that the labels are correct for items in the intersection
            for (auto &item : int_items) {
                auto where = find(query_vec.begin(), query_vec.end(), item);
                auto idx = distance(query_vec.begin(), where);

                auto reference_label = find_if(
                    all_item_labels.begin(), all_item_labels.end(), [&item](auto &item_label) {
                        return item == item_label.first;
                    });
                if (all_item_labels.end() == reference_label) {
                    std::cerr << "Reference label was not found" << std::endl;
                    return false;
                }

                size_t label_byte_count = reference_label->second.size();
                if (label_byte_count != query_result[idx].label.get_as<unsigned char>().size()) {
                    std::cerr << "Label byte count is not correct" << std::endl;
                    return false;
                }

                if (!equal(
                        reference_label->second.begin(),
                        reference_label->second.end(),
                        query_result[idx].label.get_as<unsigned char>().begin())) {
                    std::cerr << "Label does not match reference label" << std::endl;
                    return false;
                }
            }

            return true;
        }

        void RunUnlabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_clients,
            size_t num_threads)
        {
            Log::SetConsoleDisabled(true);
            Log::SetLogLevel(Log::Level::info);

            ThreadPoolMgr::SetThreadCount(num_threads);
            ThreadPoolMgr::SetPhysThreadCount(num_threads * 2);

            vector<Item> sender_items;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.push_back({ i + 1, i + 1 });
            }

            auto sender_db = make_shared<SenderDB>(params, 0);
            sender_db->set_data(sender_items);
            APSI_LOG_INFO("Packing rate: " << sender_db->get_packing_rate());

            unique_ptr<stringstream> ss = make_unique<stringstream>();
            sender_db->save(*ss);
            sender_db = nullptr;
            auto loaded_sender_db = make_shared<SenderDB>(SenderDB::Load(*ss).first);
            ss = nullptr;

            atomic<bool> stop_sender{ false };

            future<void> sender_f = async(launch::async, [&]() {
                ZMQSenderDispatcher dispatcher(loaded_sender_db);
                dispatcher.run(stop_sender, 5550);
            });

            string conn_addr = "tcp://localhost:5550";

            for (auto client_total_and_int_size : client_total_and_int_sizes) {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                vector<vector<Item>> recvs_items(num_clients);
                vector<vector<Item>> recvs_int_items(num_clients);

                for (size_t idx = 0; idx < num_clients; idx++) {
                    recvs_int_items[idx] = APSITests::rand_subset(sender_items, int_size);
                    for (auto item : recvs_int_items[idx]) {
                        recvs_items[idx].push_back(item);
                    }
                    for (size_t i = int_size; i < client_size; i++) {
                        recvs_items[idx].push_back({ i + 1, ~(i + 1) });
                    }
                }

                vector<future<bool>> futures(num_clients);
                for (size_t i = 0; i < num_clients; i++) {
                    futures[i] = async(launch::async, [&, i]() {
                        ZMQReceiverChannel recv_chl;
                        recv_chl.connect(conn_addr);

                        Receiver receiver(params);

                        vector<HashedItem> hashed_recv_items;
                        vector<LabelKey> label_keys;
                        tie(hashed_recv_items, label_keys) =
                            Receiver::RequestOPRF(recvs_items[i], recv_chl);
                        auto query_result =
                            receiver.request_query(hashed_recv_items, label_keys, recv_chl);

                        return verify_unlabeled_results(
                            query_result, recvs_items[i], recvs_int_items[i]);
                    });
                }

                for (auto &f : futures) {
                    ASSERT_TRUE(f.get());
                }
            }

            stop_sender = true;
            sender_f.get();
        }

        void RunLabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_clients,
            size_t num_threads)
        {
            Log::SetConsoleDisabled(true);
            Log::SetLogLevel(Log::Level::info);

            ThreadPoolMgr::SetThreadCount(num_threads);
            ThreadPoolMgr::SetPhysThreadCount(num_threads * 2);

            vector<pair<Item, Label>> sender_items;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.push_back(make_pair(
                    Item(i + 1, i + 1),
                    create_label(seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), 10)));
            }

            auto sender_db = make_shared<SenderDB>(params, 10, 4, true);
            sender_db->set_data(sender_items);
            APSI_LOG_INFO("Packing rate: " << sender_db->get_packing_rate());

            unique_ptr<stringstream> ss = make_unique<stringstream>();
            sender_db->save(*ss);
            sender_db = nullptr;
            auto loaded_sender_db = make_shared<SenderDB>(SenderDB::Load(*ss).first);
            ss = nullptr;

            atomic<bool> stop_sender{ false };

            future<void> sender_f = async(launch::async, [&]() {
                ZMQSenderDispatcher dispatcher(loaded_sender_db);
                dispatcher.run(stop_sender, 5550);
            });

            string conn_addr = "tcp://localhost:5550";

            for (auto client_total_and_int_size : client_total_and_int_sizes) {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                vector<vector<Item>> recv_int_items(num_clients);
                vector<vector<Item>> recv_items(num_clients);

                for (size_t idx = 0; idx < num_clients; idx++) {
                    recv_int_items[idx] = APSITests::rand_subset(sender_items, int_size);
                    for (auto item : recv_int_items[idx]) {
                        recv_items[idx].push_back(item);
                    }
                    for (size_t i = int_size; i < client_size; i++) {
                        recv_items[idx].push_back({ i + 1, ~(i + 1) });
                    }
                }

                vector<future<bool>> futures(num_clients);
                for (size_t i = 0; i < num_clients; i++) {
                    futures[i] = async(launch::async, [&, i]() {
                        ZMQReceiverChannel recv_chl;
                        recv_chl.connect(conn_addr);

                        Receiver receiver(params);

                        vector<HashedItem> hashed_recv_items;
                        vector<LabelKey> label_keys;
                        tie(hashed_recv_items, label_keys) =
                            Receiver::RequestOPRF(recv_items[i], recv_chl);
                        auto query_result =
                            receiver.request_query(hashed_recv_items, label_keys, recv_chl);

                        return verify_labeled_results(
                            query_result, recv_items[i], recv_int_items[i], sender_items);
                    });
                }

                for (auto &f : futures) {
                    ASSERT_TRUE(f.get());
                }
            }

            stop_sender = true;
            sender_f.get();
        }
    } // namespace

    TEST(ZMQSenderReceiverTests, UnlabeledEmpty)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledEmptyMultiThreaded)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, params, 1, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingle)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingleMultiThreaded)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmall)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 5, 0 },
              { 5, 2 },
              { 5, 5 },
              { 10, 0 },
              { 10, 5 },
              { 10, 10 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmallMultiThreaded)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 5, 0 },
              { 5, 2 },
              { 5, 5 },
              { 10, 0 },
              { 10, 5 },
              { 10, 10 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMedium)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 50, 10 },
              { 50, 50 },
              { 100, 1 },
              { 100, 50 },
              { 100, 100 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMediumMultiThreaded)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 50, 10 },
              { 50, 50 },
              { 100, 1 },
              { 100, 50 },
              { 100, 100 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledLarge)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledLargeMultiThreaded)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledLargeMultiThreadedMultiClient)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledHugeMultiThreaded)
    {
        size_t sender_size = 50000;
        PSIParams params = create_huge_params();
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 5000, 100 },
              { 5000, 5000 },
              { 10000, 0 },
              { 10000, 5000 },
              { 10000, 10000 },
              { 50000, 50000 } },
            params,
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size, { { 10000, 10000 } }, params, 1, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledEmpty)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledEmptyMultiThreaded)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, params, 1, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSingle)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSingleMultiThreaded)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSmall)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 5, 0 },
              { 5, 2 },
              { 5, 5 },
              { 10, 0 },
              { 10, 5 },
              { 10, 10 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSmallMultiThreaded)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 5, 0 },
              { 5, 2 },
              { 5, 5 },
              { 10, 0 },
              { 10, 5 },
              { 10, 10 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledMedium)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 50, 10 },
              { 50, 50 },
              { 100, 1 },
              { 100, 50 },
              { 100, 100 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledMediumMultiThreaded)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 1, 1 },
              { 50, 10 },
              { 50, 50 },
              { 100, 1 },
              { 100, 50 },
              { 100, 100 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledLarge)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledLargeMultiThreaded)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledLargeMultiThreadedMultiClient)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 500, 10 },
              { 500, 50 },
              { 500, 500 },
              { 1000, 0 },
              { 1000, 1 },
              { 1000, 500 },
              { 1000, 999 },
              { 1000, 1000 } },
            params,
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledHugeMultiThreaded)
    {
        size_t sender_size = 50000;
        PSIParams params = create_huge_params();
        RunLabeledTest(
            sender_size,
            { { 0, 0 },
              { 1, 0 },
              { 5000, 100 },
              { 5000, 5000 },
              { 10000, 0 },
              { 10000, 5000 },
              { 10000, 10000 },
              { 50000, 50000 } },
            params,
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size, { { 10000, 10000 } }, params, 1, thread::hardware_concurrency());
    }
} // namespace APSITests
