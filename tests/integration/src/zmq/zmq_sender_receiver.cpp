// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <future>
#include <memory>
#include <sstream>
#include <string>

// APSI
#include "apsi/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "support/zmq_test_utils.h"
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
        /**
        A running dispatcher together with the address its clients should connect to.
        */
        struct RunningDispatcher {
            std::future<void> done;

            std::string conn_addr;
        };

        /**
        Starts a dispatcher on a port chosen by the operating system and waits until it is
        listening, so that the address returned is one a client can actually connect to.

        The port cannot be hard-coded: a fixed one collides with any other test binary running
        at the same time. It is therefore only settled at bind time, which is why the caller has
        to wait for it here. Should the dispatcher fail before it ever binds, that failure is
        what surfaces, rather than a wait for an address that will never arrive.
        */
        RunningDispatcher start_dispatcher(
            const std::shared_ptr<SenderDB> &sender_db, const std::atomic<bool> &stop)
        {
            auto port = std::make_shared<std::promise<int>>();
            std::future<int> bound_port = port->get_future();

            std::future<void> done = async(launch::async, [sender_db, &stop, port] {
                try {
                    ZMQSenderDispatcher dispatcher(sender_db);
                    dispatcher.run(
                        stop, 0, [port](int listening_port) { port->set_value(listening_port); });
                } catch (...) {
                    try {
                        port->set_exception(std::current_exception());
                    } catch (const std::future_error &) { // NOLINT(bugprone-empty-catch): see below
                        // The port was already reported, so the dispatcher bound successfully
                        // and failed later. Nobody is waiting on the promise any more.
                    }
                    throw;
                }
            });

            return { std::move(done), connect_address(bound_port.get()) };
        }

        bool verify_unlabeled_results(
            const vector<MatchRecord> &query_result,
            const vector<Item> &query_vec,
            const vector<Item> &int_items)
        {
            // Count matches
            size_t match_count = accumulate(
                query_result.cbegin(),
                query_result.cend(),
                static_cast<size_t>(0),
                [](auto sum, auto &curr) { return sum + curr.found; });

            // Check that intersection size is correct
            if (int_items.size() != match_count) {
                cerr << "intersection size is not correct" << '\n';
                return false;
            }

            // Check that every intersection item was actually found
            for (const auto &item : int_items) {
                auto where = find(query_vec.begin(), query_vec.end(), item);
                if (query_vec.end() == where) {
                    cerr << "Could not find intersection item" << '\n';
                    return false;
                }

                size_t idx = static_cast<size_t>(distance(query_vec.begin(), where));
                if (!query_result[idx].found) {
                    cerr << "Query result should be found" << '\n';
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
            for (const auto &result : query_result) {
                if (result.found) {
                    if (!result.label) {
                        cerr << "Label does not contain data" << '\n';
                        return false;
                    }
                }
            }

            // Check that the labels are correct for items in the intersection
            for (const auto &item : int_items) {
                auto where = find(query_vec.begin(), query_vec.end(), item);
                size_t idx = static_cast<size_t>(distance(query_vec.begin(), where));

                auto reference_label = find_if(
                    all_item_labels.begin(), all_item_labels.end(), [&item](auto &item_label) {
                        return item == item_label.first;
                    });
                if (all_item_labels.end() == reference_label) {
                    cerr << "Reference label was not found" << '\n';
                    return false;
                }

                size_t label_byte_count = reference_label->second.size();
                if (label_byte_count != query_result[idx].label.value().size()) {
                    cerr << "Label byte count is not correct" << '\n';
                    return false;
                }

                if (!equal(
                        reference_label->second.begin(),
                        reference_label->second.end(),
                        query_result[idx].label.value().begin())) {
                    cerr << "Label does not match reference label" << '\n';
                    return false;
                }
            }

            return true;
        }

        void RunUnlabeledTest(
            size_t sender_size,
            const vector<pair<size_t, size_t>> &client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_clients,
            size_t num_threads)
        {
            SetLogger(Logger::Create({}, {}, {})); // null logger: suppress test output
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(num_threads);
            ThreadPoolMgr::SetPoolWorkerCount(num_threads * 2);

            vector<Item> sender_items;
            sender_items.reserve(sender_size);
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(i + 1, i + 1);
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

            RunningDispatcher sender = start_dispatcher(loaded_sender_db, stop_sender);
            const string &conn_addr = sender.conn_addr;

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
                        recvs_items[idx].emplace_back(i + 1, ~(i + 1));
                    }
                }

                vector<future<bool>> futures(num_clients);
                for (size_t i = 0; i < num_clients; i++) {
                    futures[i] = async(launch::async, [&, i] {
                        ZMQReceiverChannel recv_chl;
                        recv_chl.connect(conn_addr);

                        Receiver receiver(params);

                        auto [hashed_recv_items, label_keys] =
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
            sender.done.get();
        }

        void RunLabeledTest(
            size_t sender_size,
            const vector<pair<size_t, size_t>> &client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_clients,
            size_t num_threads)
        {
            SetLogger(Logger::Create({}, {}, {})); // null logger: suppress test output
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(num_threads);
            ThreadPoolMgr::SetPoolWorkerCount(num_threads * 2);

            vector<pair<Item, Label>> sender_items;
            sender_items.reserve(sender_size);
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(
                    Item(i + 1, i + 1),
                    create_label(seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), 10));
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

            RunningDispatcher sender = start_dispatcher(loaded_sender_db, stop_sender);
            const string &conn_addr = sender.conn_addr;

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
                        recv_items[idx].emplace_back(i + 1, ~(i + 1));
                    }
                }

                vector<future<bool>> futures(num_clients);
                for (size_t i = 0; i < num_clients; i++) {
                    futures[i] = async(launch::async, [&, i] {
                        ZMQReceiverChannel recv_chl;
                        recv_chl.connect(conn_addr);

                        Receiver receiver(params);

                        auto [hashed_recv_items, label_keys] =
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
            sender.done.get();
        }
    } // namespace

    TEST(ZMQSenderReceiverTests, UnlabeledEmpty1)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledEmpty2)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledEmptyMultiThreaded1)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 } },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledEmptyMultiThreaded2)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 } },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingle1)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params1(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingle2)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params2(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingleMultiThreaded1)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingleMultiThreaded2)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmall1)
    {
        size_t sender_size = 10;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmall2)
    {
        size_t sender_size = 10;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmallMultiThreaded1)
    {
        size_t sender_size = 10;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmallMultiThreaded2)
    {
        size_t sender_size = 10;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMedium1)
    {
        size_t sender_size = 500;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMedium2)
    {
        size_t sender_size = 500;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMediumMultiThreaded1)
    {
        size_t sender_size = 500;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMediumMultiThreaded2)
    {
        size_t sender_size = 500;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLarge1)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLarge2)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreaded1)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreaded2)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreadedMultiClient1)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreadedMultiClient2)
    {
        size_t sender_size = 4000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledHugeMultiThreaded1)
    {
        size_t sender_size = 50000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 5000, 100 },
                { 5000, 5000 },
                { 10000, 0 },
                { 10000, 5000 },
                { 10000, 10000 },
                { 50000, 50000 },
            },
            create_huge_params1(),
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_UnlabeledHugeMultiThreaded2)
    {
        size_t sender_size = 50000;
        RunUnlabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 5000, 100 },
                { 5000, 5000 },
                { 10000, 0 },
                { 10000, 5000 },
                { 10000, 10000 },
                { 50000, 50000 },
            },
            create_huge_params2(),
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledEmpty1)
    {
        size_t sender_size = 0;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledEmpty2)
    {
        size_t sender_size = 0;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledEmptyMultiThreaded1)
    {
        size_t sender_size = 0;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 } },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledEmptyMultiThreaded2)
    {
        size_t sender_size = 0;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 } },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSingle1)
    {
        size_t sender_size = 1;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params1(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSingle2)
    {
        size_t sender_size = 1;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params2(), 1, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSingleMultiThreaded1)
    {
        size_t sender_size = 1;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSingleMultiThreaded2)
    {
        size_t sender_size = 1;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSmall1)
    {
        size_t sender_size = 10;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSmall2)
    {
        size_t sender_size = 10;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSmallMultiThreaded1)
    {
        size_t sender_size = 10;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSmallMultiThreaded2)
    {
        size_t sender_size = 10;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 5, 0 },
                { 5, 2 },
                { 5, 5 },
                { 10, 0 },
                { 10, 5 },
                { 10, 10 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledMedium1)
    {
        size_t sender_size = 500;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledMedium2)
    {
        size_t sender_size = 500;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, LabeledMediumMultiThreaded1)
    {
        size_t sender_size = 500;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledMediumMultiThreaded2)
    {
        size_t sender_size = 500;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 1, 1 },
                { 50, 10 },
                { 50, 50 },
                { 100, 1 },
                { 100, 50 },
                { 100, 100 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLarge1)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLarge2)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            1,
            1);
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLargeMultiThreaded1)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLargeMultiThreaded2)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLargeMultiThreadedMultiClient1)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params1(),
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledLargeMultiThreadedMultiClient2)
    {
        size_t sender_size = 4000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 500, 10 },
                { 500, 50 },
                { 500, 500 },
                { 1000, 0 },
                { 1000, 1 },
                { 1000, 500 },
                { 1000, 999 },
                { 1000, 1000 },
            },
            create_params2(),
            10,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledHugeMultiThreaded1)
    {
        size_t sender_size = 50000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 5000, 100 },
                { 5000, 5000 },
                { 10000, 0 },
                { 10000, 5000 },
                { 10000, 10000 },
                { 50000, 50000 },
            },
            create_huge_params1(),
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            1,
            thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, DISABLED_LabeledHugeMultiThreaded2)
    {
        size_t sender_size = 50000;
        RunLabeledTest(
            sender_size,
            {
                { 0, 0 },
                { 1, 0 },
                { 5000, 100 },
                { 5000, 5000 },
                { 10000, 0 },
                { 10000, 5000 },
                { 10000, 10000 },
                { 50000, 50000 },
            },
            create_huge_params2(),
            1,
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params2(),
            1,
            thread::hardware_concurrency());
    }
} // namespace APSITests
