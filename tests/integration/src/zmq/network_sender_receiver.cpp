// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <memory>
#include <random>
#include <vector>
#include <algorithm>

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
    map<size_t, Item> rand_subset(const unordered_set<Item> &items, size_t size)
    {
        random_device rd;

        set<size_t> ss;
        while (ss.size() != size)
        {
            ss.emplace(static_cast<size_t>(rd() % items.size()));
        }

        vector<Item> items_vec(items.begin(), items.end());
        map<size_t, Item> items_subset;
        for (auto idx : ss)
        {
            items_subset[idx] = items_vec[idx];
        }

        return items_subset;
    }

    void verify_psi_results(
        const vector<MatchRecord> &query_result, const vector<Item> &query_subset)
    {
        ASSERT_EQ(query_subset.size(), query_result.size());

        // Count matches
        size_t match_count = accumulate(query_result.cbegin(), query_result.cend(), size_t(0),
            [](auto sum, auto &curr) { return sum + !!curr; });

        // All items were found
        ASSERT_EQ(query_subset.size(), match_count);
    }

    void verify_labeled_psi_results(
        const vector<MatchRecord> &query_result, const vector<Item> &query_subset,
        const vector<FullWidthLabel> &total_label_set)
    {
        verify_psi_results(query_result, query_subset);

        // Check that all labels in the query subset match
        for (size_t idx = 0; idx < query_result.size(); idx++)
        {
            auto result_label = query_result[idx].label.get_as<uint64_t>();
            auto reference_label = gsl::span<const uint64_t>(
                total_label_set[idx].data(),
                sizeof(FullWidthLabel)/sizeof(uint64_t));
            ASSERT_TRUE(equal(reference_label.begin(), reference_label.end(), result_label.begin()));
        }
    }

    void RunTest(size_t sender_size, size_t client_size, const PSIParams &params, size_t num_threads)
    {
        logging::Log::set_log_level(logging::Log::Level::level_all);
        logging::Log::set_console_disabled(false);

        unordered_set<Item> sender_items;
        for (size_t i = 0; i < sender_size; i++)
        {
            sender_items.emplace(kuku::make_item(i + 1, 0));
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

        // Connect the network
        ReceiverChannel recv_chl;

        string conn_addr = "tcp://localhost:5550";
        recv_chl.connect(conn_addr);

        Receiver receiver(params, num_threads);
        auto recv_items = rand_subset(sender_items, client_size);
        vector<Item> recv_items_vec;
        for (auto item : recv_items)
        {
            recv_items_vec.push_back(item.second);
        }

        auto hashed_recv_items = receiver.request_oprf(recv_items_vec, recv_chl);
        auto query = receiver.create_query(hashed_recv_items);
        auto query_result = receiver.request_query(move(query), recv_chl);

        stop_sender = true;
        sender_th.join();

        verify_psi_results(query_result, recv_items_vec);
    }

    PSIParams create_params()
    {
        //logging::Log::set_console_disabled(true);
        //logging::Log::set_log_level(logging::Log::Level::level_debug);
        //logging::Log::set_log_file("out.log");

        PSIParams::ItemParams item_params;
        item_params.felts_per_item = 8;

        PSIParams::TableParams table_params;
        table_params.hash_func_count = 3;
        table_params.max_items_per_bin = 16;
        table_params.table_size = 4096;

        PSIParams::QueryParams query_params;
        query_params.query_powers_count = 3;

        PSIParams::SEALParams seal_params(scheme_type::bfv);
        seal_params.set_poly_modulus_degree(8192);
        seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
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
        RunTest(sender_size, 0, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledEmptyMultiThreadedTest)
    {
        size_t sender_size = 0;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 4);
    }

    TEST(SenderReceiverTests, UnlabeledSingleTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 1);
        RunTest(sender_size, 1, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledSingleMultiThreadedTest)
    {
        size_t sender_size = 1;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 4);
        RunTest(sender_size, 1, params, 4);
    }

    TEST(SenderReceiverTests, UnlabeledSmallTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 1);
        RunTest(sender_size, 1, params, 1);
        RunTest(sender_size, 5, params, 1);
        RunTest(sender_size, 10, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledSmallMultiThreadedTest)
    {
        size_t sender_size = 10;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 4);
        RunTest(sender_size, 1, params, 4);
        RunTest(sender_size, 5, params, 4);
        RunTest(sender_size, 10, params, 4);
    }

    TEST(SenderReceiverTests, UnlabeledMediumTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 1);
        RunTest(sender_size, 1, params, 1);
        RunTest(sender_size, 50, params, 1);
        RunTest(sender_size, 100, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledMediumMultiThreadedTest)
    {
        size_t sender_size = 500;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 4);
        RunTest(sender_size, 1, params, 4);
        RunTest(sender_size, 50, params, 4);
        RunTest(sender_size, 100, params, 4);
    }

    TEST(SenderReceiverTests, UnlabeledLargeTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 1);
        RunTest(sender_size, 1, params, 1);
        RunTest(sender_size, 500, params, 1);
        RunTest(sender_size, 1000, params, 1);
    }

    TEST(SenderReceiverTests, UnlabeledLargeMultiThreadedTest)
    {
        size_t sender_size = 4000;
        PSIParams params = create_params();
        RunTest(sender_size, 0, params, 4);
        RunTest(sender_size, 1, params, 4);
        RunTest(sender_size, 500, params, 4);
        RunTest(sender_size, 1000, params, 4);
    }
} // namespace APSITests
