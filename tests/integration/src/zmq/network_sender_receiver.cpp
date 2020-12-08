// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <memory>
#include <random>
#include <vector>
#include <algorithm>
#include <array>
#include <iterator>
#include <unordered_set>
#include <unordered_map>

// APSI
#include "apsi/logging/log.h"
#include "apsi/network/zmq/network_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/senderdb.h"
#include "apsi/zmq/sender_dispatcher.h"
#include "apsi/util/utils.h"

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

namespace
{
    unordered_set<Item> rand_subset(const unordered_set<Item> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }

        vector<Item> items_vec(items.begin(), items.end());
        unordered_set<Item> items_subset;
        for (auto idx : ss)
        {
            items_subset.insert(items_vec[idx]);
        }

        return items_subset;
    }

    unordered_set<Item> rand_subset(const unordered_map<Item, FullWidthLabel> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }

        vector<Item> items_vec;
        transform(items.begin(), items.end(), back_inserter(items_vec), [](auto &item) { return item.first; });
        unordered_set<Item> items_subset;
        for (auto idx : ss)
        {
            items_subset.insert(items_vec[idx]);
        }

        return items_subset;
    }

    void verify_unlabeled_results(
        const vector<MatchRecord> &query_result,
        const vector<Item> &query_vec,
        const unordered_set<Item> &int_items
    ) {
        // Count matches
        size_t match_count = accumulate(query_result.cbegin(), query_result.cend(), size_t(0),
            [](auto sum, auto &curr) { return sum + curr.found; });

        // Check that intersection size is correct
        ASSERT_EQ(int_items.size(), match_count);

        // Check that every intersection item was actually found
        for (auto &item : int_items)
        {
            auto where = find(query_vec.begin(), query_vec.end(), item);
            ASSERT_NE(query_vec.end(), where);

            auto idx = distance(query_vec.begin(), where);
            ASSERT_TRUE(query_result[idx].found);
        }
    }

    void verify_labeled_results(
        const vector<MatchRecord> &query_result,
        const vector<Item> &query_vec,
        const unordered_set<Item> &int_items,
        const unordered_map<Item, FullWidthLabel> &all_item_labels
    ) {
        verify_unlabeled_results(query_result, query_vec, int_items);

        // Verify that all labels were received for items that were found
        for (auto &result : query_result)
        {
            if (result.found)
            {
                ASSERT_TRUE(result.label);

            }
        }

        // Check that the labels are correct for items in the intersection
        for (auto &item : int_items)
        {
            auto where = find(query_vec.begin(), query_vec.end(), item);
            auto idx = distance(query_vec.begin(), where);

            auto reference_label = find_if(
                all_item_labels.begin(),
                all_item_labels.end(),
                [&item](auto &item_label) { return item == item_label.first; });
            ASSERT_NE(all_item_labels.end(), reference_label);

            array<uint64_t, 2> label;
            copy_n(query_result[idx].label.get_as<uint64_t>().begin(), 2, label.begin());
            ASSERT_EQ(reference_label->second.value(), label);
        }
    }

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
            SenderDispatcher dispatcher(sender_db, num_threads);
            dispatcher.run(stop_sender, 5550, oprf_key);
        });

        ReceiverChannel recv_chl;

        string conn_addr = "tcp://localhost:5550";
        recv_chl.connect(conn_addr);

        Receiver receiver(params, num_threads);

        for (auto client_total_and_int_size : client_total_and_int_sizes)
        {
            auto client_size = client_total_and_int_size.first;
            auto int_size = client_total_and_int_size.second;
            ASSERT_TRUE(int_size <= client_size);

            unordered_set<Item> recv_int_items = rand_subset(sender_items, int_size);
            vector<Item> recv_items;
            for (auto item : recv_int_items)
            {
                recv_items.push_back(item);
            }
            for (size_t i = int_size; i < client_size; i++)
            {
                recv_items.push_back({ i + 1, ~(i + 1) });
            }

            auto hashed_recv_items = receiver.request_oprf(recv_items, recv_chl);
            auto query = receiver.create_query(hashed_recv_items);
            auto query_result = receiver.request_query(move(query), recv_chl);

            verify_unlabeled_results(query_result, recv_items, recv_int_items);
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
            SenderDispatcher dispatcher(sender_db, num_threads);
            dispatcher.run(stop_sender, 5550, oprf_key);
        });

        ReceiverChannel recv_chl;

        string conn_addr = "tcp://localhost:5550";
        recv_chl.connect(conn_addr);

        Receiver receiver(params, num_threads);

        for (auto client_total_and_int_size : client_total_and_int_sizes)
        {
            auto client_size = client_total_and_int_size.first;
            auto int_size = client_total_and_int_size.second;
            ASSERT_TRUE(int_size <= client_size);

            unordered_set<Item> recv_int_items = rand_subset(sender_items, int_size);
            vector<Item> recv_items;
            for (auto item : recv_int_items)
            {
                recv_items.push_back(item);
            }
            for (size_t i = int_size; i < client_size; i++)
            {
                recv_items.push_back({ i + 1, ~(i + 1) });
            }

            auto hashed_recv_items = receiver.request_oprf(recv_items, recv_chl);
            auto query = receiver.create_query(hashed_recv_items);
            auto query_result = receiver.request_query(move(query), recv_chl);

            verify_labeled_results(query_result, recv_items, recv_int_items, sender_items);
        }

        stop_sender = true;
        sender_th.join();
    }

    PSIParams create_params()
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 4096;

        PSIParams::QueryParams query_params;
        query_params.query_powers_count = 3;

        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(8192);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
        seal_params.set_plain_modulus(65537);

        return { item_params, table_params, query_params, seal_params };
    }

    PSIParams create_huge_params()
    {
        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 4;
        table_params.max_items_per_bin = 128;
        table_params.table_size = 65536;

        PSIParams::QueryParams query_params;
        query_params.query_powers_count = 3;

        PSIParams::SEALParams seal_params;
        seal_params.set_poly_modulus_degree(16384);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(16384));
        seal_params.set_plain_modulus(65537);

        return { item_params, table_params, query_params, seal_params };
    }
} // namespace

namespace APSITests
{
    TEST(SenderReceiverTests, UnlabeledEmptyTest)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledEmptyMultiThreadedTest)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, UnlabeledSingleTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledSingleMultiThreadedTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, UnlabeledSmallTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledSmallMultiThreadedTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, UnlabeledMediumTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledMediumMultiThreadedTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, UnlabeledLargeTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledLargeMultiThreadedTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunUnlabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, UnlabeledHugeMultiThreadedTest)
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

    TEST(SenderReceiverTests, LabeledEmptyTest)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, 1);
    }

    TEST(SenderReceiverTests, LabeledEmptyMultiThreadedTest)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, LabeledSingleTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, 1);
    }

    TEST(SenderReceiverTests, LabeledSingleMultiThreadedTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, LabeledSmallTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, 1);
    }

    TEST(SenderReceiverTests, LabeledSmallMultiThreadedTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 5, 0 }, { 5, 2 }, { 5, 5 }, { 10, 0 }, { 10, 5 }, { 10, 10 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, LabeledMediumTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, 1);
    }

    TEST(SenderReceiverTests, LabeledMediumMultiThreadedTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 50, 10 }, { 50, 50 }, { 100, 1 }, { 100, 50 }, { 100, 100 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, LabeledLargeTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, 1);
    }

    TEST(SenderReceiverTests, LabeledLargeMultiThreadedTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunLabeledTest(sender_size,
            { { 0, 0 }, { 1, 0 }, { 500, 10 }, { 500, 50 }, { 500, 500 }, { 1000, 0 }, { 1000, 1 }, { 1000, 500 },
                { 1000, 999 }, { 1000, 1000 } },
            params, thread::hardware_concurrency());
    }

    TEST(SenderReceiverTests, LabeledHugeMultiThreadedTest)
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
