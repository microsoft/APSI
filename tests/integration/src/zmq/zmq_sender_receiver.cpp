// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "test_utils.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace apsi::network;
using namespace apsi::util;
using namespace apsi::logging;
using namespace apsi::oprf;
using namespace seal;

namespace APSITests
{
    namespace
    {
        void RunUnlabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads)
        {
            logging::Log::set_console_disabled(false);
            logging::Log::set_log_level(logging::Log::Level::info);
            //logging::Log::set_log_file("out.log");

            unordered_set<Item> sender_items;
            for (size_t i = 0; i < sender_size; i++)
            {
                sender_items.insert({ i + 1, i + 1 });
            }

            auto oprf_key = make_shared<OPRFKey>();
            auto hashed_sender_items = OPRFSender::ComputeHashes(sender_items, *oprf_key);

            auto sender_db = make_shared<UnlabeledSenderDB>(params);
            sender_db->set_data(hashed_sender_items, num_threads);

            atomic<bool> stop_sender = false;

            auto sender_th = thread([&]() {
                ZMQSenderDispatcher dispatcher(sender_db, num_threads);
                dispatcher.run(stop_sender, 5550, oprf_key);
            });

            ZMQReceiverChannel recv_chl;

            string conn_addr = "tcp://localhost:5550";
            recv_chl.connect(conn_addr);

            Receiver receiver(params, num_threads);

            for (auto client_total_and_int_size : client_total_and_int_sizes)
            {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                unordered_set<Item> recv_int_items = APSITests::rand_subset(sender_items, int_size);
                vector<Item> recv_items;
                for (auto item : recv_int_items)
                {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++)
                {
                    recv_items.push_back({ i + 1, ~(i + 1) });
                }

                auto hashed_recv_items =Receiver::RequestOPRF(recv_items, recv_chl);
                auto query_result = receiver.request_query(hashed_recv_items, recv_chl);

                APSITests::verify_unlabeled_results(query_result, recv_items, recv_int_items);
            }

            stop_sender = true;
            sender_th.join();
        }

        void RunLabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads)
        {
            logging::Log::set_console_disabled(false);
            logging::Log::set_log_level(logging::Log::Level::info);
            //logging::Log::set_log_file("out.log");

            unordered_map<Item, FullWidthLabel> sender_items;
            for (size_t i = 0; i < sender_size; i++)
            {
                sender_items.insert(make_pair(Item(i + 1, i + 1), FullWidthLabel(~(i + 1), i + 1)));
            }

            auto oprf_key = make_shared<OPRFKey>();
            auto hashed_sender_items = OPRFSender::ComputeHashes(sender_items, *oprf_key);

            auto sender_db = make_shared<LabeledSenderDB>(params);
            sender_db->set_data(hashed_sender_items, num_threads);

            atomic<bool> stop_sender = false;

            auto sender_th = thread([&]() {
                ZMQSenderDispatcher dispatcher(sender_db, num_threads);
                dispatcher.run(stop_sender, 5550, oprf_key);
            });

            ZMQReceiverChannel recv_chl;

            string conn_addr = "tcp://localhost:5550";
            recv_chl.connect(conn_addr);

            Receiver receiver(params, num_threads);

            for (auto client_total_and_int_size : client_total_and_int_sizes)
            {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                unordered_set<Item> recv_int_items = APSITests::rand_subset(sender_items, int_size);
                vector<Item> recv_items;
                for (auto item : recv_int_items)
                {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++)
                {
                    recv_items.push_back({ i + 1, ~(i + 1) });
                }

                auto hashed_recv_items = Receiver::RequestOPRF(recv_items, recv_chl);
                auto query_result = receiver.request_query(hashed_recv_items, recv_chl);

                APSITests::verify_labeled_results(query_result, recv_items, recv_int_items, sender_items);
            }

            stop_sender = true;
            sender_th.join();
        }
    }
    
    TEST(ZMQSenderReceiverTests, UnlabeledEmpty)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledEmptyMultiThreaded)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingle)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSingleMultiThreaded)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmall)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledSmallMultiThreaded)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMedium)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledMediumMultiThreaded)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledLarge)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, UnlabeledLargeMultiThreaded)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, UnlabeledHugeMultiThreaded)
    {
        size_t sender_size = 50000;
        PSIParams params = create_huge_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 5000, 100 }, { 5000, 5000 }, { 10000, 0 }, { 10000, 5000 }, { 10000, 10000 },
                { 50000, 50000 } },
            params, thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(sender_size, { { 10000, 10000 } }, params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledEmpty)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledEmptyMultiThreaded)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSingle)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSingleMultiThreaded)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledSmall)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledSmallMultiThreaded)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledMedium)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledMediumMultiThreaded)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledLarge)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, 1);
    }

    TEST(ZMQSenderReceiverTests, LabeledLargeMultiThreaded)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, thread::hardware_concurrency());
    }

    TEST(ZMQSenderReceiverTests, LabeledHugeMultiThreaded)
    {
        size_t sender_size = 50000;
        PSIParams params = create_huge_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 5000, 100 }, { 5000, 5000 }, { 10000, 0 }, { 10000, 5000 }, { 10000, 10000 },
                { 50000, 50000 } },
            params, thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(sender_size, { { 10000, 10000 } }, params, thread::hardware_concurrency());
    }
} // namespace APSITests
