// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>

// APSI
#include "apsi/log.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
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
        void RunUnlabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads,
            bool use_different_compression = false)
        {
            Log::SetConsoleDisabled(true);
            Log::SetLogLevel(Log::Level::info);

            ThreadPoolMgr::SetThreadCount(num_threads);

            vector<Item> sender_items;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.push_back({ i + 1, i + 1 });
            }

            auto sender_db = make_shared<SenderDB>(params, 0);
            auto oprf_key = sender_db->get_oprf_key();

            sender_db->set_data(sender_items);

            auto seal_context = sender_db->get_seal_context();

            stringstream ss;
            StreamChannel chl(ss);

            Receiver receiver(params);

            for (auto client_total_and_int_size : client_total_and_int_sizes) {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                vector<Item> recv_int_items = rand_subset(sender_items, int_size);
                vector<Item> recv_items;
                for (auto item : recv_int_items) {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++) {
                    recv_items.push_back({ i + 1, ~(i + 1) });
                }

                // Create the OPRF receiver
                oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
                Request oprf_request = Receiver::CreateOPRFRequest(oprf_receiver);

                // Send the OPRF request
                ASSERT_NO_THROW(chl.send(move(oprf_request)));
                size_t bytes_sent = chl.bytes_sent();

                // Receive the OPRF request and process response
                OPRFRequest oprf_request2 =
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
                size_t bytes_received = chl.bytes_received();
                ASSERT_EQ(bytes_sent, bytes_received);
                ASSERT_NO_THROW(Sender::RunOPRF(oprf_request2, oprf_key, chl));

                // Receive OPRF response
                OPRFResponse oprf_response = to_oprf_response(chl.receive_response());
                vector<HashedItem> hashed_recv_items;
                vector<LabelKey> label_keys;
                tie(hashed_recv_items, label_keys) =
                    Receiver::ExtractHashes(oprf_response, oprf_receiver);
                ASSERT_EQ(hashed_recv_items.size(), recv_items.size());

                // Create query and send
                pair<Request, IndexTranslationTable> recv_query_pair =
                    receiver.create_query(hashed_recv_items);

                QueryRequest recv_query = to_query_request(move(recv_query_pair.first));
                compr_mode_type expected_compr_mode = recv_query->compr_mode;

                if (use_different_compression &&
                    Serialization::IsSupportedComprMode(compr_mode_type::zlib) &&
                    Serialization::IsSupportedComprMode(compr_mode_type::zstd)) {
                    if (recv_query->compr_mode == compr_mode_type::zstd) {
                        recv_query->compr_mode = compr_mode_type::zlib;
                        expected_compr_mode = compr_mode_type::zlib;
                    } else {
                        recv_query->compr_mode = compr_mode_type::zstd;
                        expected_compr_mode = compr_mode_type::zstd;
                    }
                }

                IndexTranslationTable itt = move(recv_query_pair.second);
                chl.send(move(recv_query));

                // Receive the query and process response
                QueryRequest sender_query = to_query_request(chl.receive_operation(seal_context));
                Query query(move(sender_query), sender_db);
                ASSERT_EQ(expected_compr_mode, query.compr_mode());
                ASSERT_NO_THROW(Sender::RunQuery(query, chl));

                // Receive query response
                QueryResponse query_response = to_query_response(chl.receive_response());
                uint32_t package_count = query_response->package_count;

                // Receive all result parts and process result
                vector<ResultPart> rps;
                while (package_count--) {
                    ASSERT_NO_THROW(rps.push_back(chl.receive_result(receiver.get_seal_context())));
                }
                auto query_result = receiver.process_result(label_keys, itt, rps);

                verify_unlabeled_results(query_result, recv_items, recv_int_items);
            }
        }

        void RunLabeledTest(
            size_t sender_size,
            vector<pair<size_t, size_t>> client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads)
        {
            Log::SetConsoleDisabled(true);
            Log::SetLogLevel(Log::Level::info);

            ThreadPoolMgr::SetThreadCount(num_threads);

            vector<pair<Item, Label>> sender_items;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.push_back(make_pair(
                    Item(i + 1, i + 1),
                    create_label(seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), 10)));
            }

            auto sender_db = make_shared<SenderDB>(params, 10, 4, true);
            sender_db->set_data(sender_items);
            auto oprf_key = sender_db->get_oprf_key();

            auto seal_context = sender_db->get_seal_context();

            stringstream ss;
            StreamChannel chl(ss);

            Receiver receiver(params);

            for (auto client_total_and_int_size : client_total_and_int_sizes) {
                auto client_size = client_total_and_int_size.first;
                auto int_size = client_total_and_int_size.second;
                ASSERT_TRUE(int_size <= client_size);

                vector<Item> recv_int_items = rand_subset(sender_items, int_size);
                vector<Item> recv_items;
                for (auto item : recv_int_items) {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++) {
                    recv_items.push_back({ i + 1, ~(i + 1) });
                }

                // Create the OPRF receiver
                oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
                Request oprf_request = Receiver::CreateOPRFRequest(oprf_receiver);

                // Send the OPRF request
                ASSERT_NO_THROW(chl.send(move(oprf_request)));
                size_t bytes_sent = chl.bytes_sent();

                // Receive the OPRF request and process response
                OPRFRequest oprf_request2 =
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
                size_t bytes_received = chl.bytes_received();
                ASSERT_EQ(bytes_sent, bytes_received);
                ASSERT_NO_THROW(Sender::RunOPRF(oprf_request2, oprf_key, chl));

                // Receive OPRF response
                OPRFResponse oprf_response = to_oprf_response(chl.receive_response());
                vector<HashedItem> hashed_recv_items;
                vector<LabelKey> label_keys;
                tie(hashed_recv_items, label_keys) =
                    Receiver::ExtractHashes(oprf_response, oprf_receiver);
                ASSERT_EQ(hashed_recv_items.size(), recv_items.size());

                // Create query and send
                pair<Request, IndexTranslationTable> recv_query =
                    receiver.create_query(hashed_recv_items);
                IndexTranslationTable itt = move(recv_query.second);
                chl.send(move(recv_query.first));

                // Receive the query and process response
                QueryRequest sender_query = to_query_request(chl.receive_operation(seal_context));
                Query query(move(sender_query), sender_db);
                ASSERT_NO_THROW(Sender::RunQuery(query, chl));

                // Receive query response
                QueryResponse query_response = to_query_response(chl.receive_response());
                uint32_t package_count = query_response->package_count;

                // Receive all result parts and process result
                vector<ResultPart> rps;
                while (package_count--) {
                    ASSERT_NO_THROW(rps.push_back(chl.receive_result(receiver.get_seal_context())));
                }
                auto query_result = receiver.process_result(label_keys, itt, rps);

                verify_labeled_results(query_result, recv_items, recv_int_items, sender_items);
            }
        }
    } // namespace

    TEST(StreamSenderReceiverTests, UnlabeledEmpty1)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), 1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledEmpty2)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), 1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledEmptyMultiThreaded1)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledEmptyMultiThreaded2)
    {
        size_t sender_size = 0;
        RunUnlabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledSingle1)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params1(), 1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSingle2)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params2(), 1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSingleMultiThreaded1)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledSingleMultiThreaded2)
    {
        size_t sender_size = 1;
        RunUnlabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmall1)
    {
        size_t sender_size = 10;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmall2)
    {
        size_t sender_size = 10;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallDifferentCompression1)
    {
        size_t sender_size = 10;
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
            create_params1(),
            1,
            true);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallDifferentCompression2)
    {
        size_t sender_size = 10;
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
            create_params2(),
            1,
            true);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallMultiThreaded1)
    {
        size_t sender_size = 10;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallMultiThreaded2)
    {
        size_t sender_size = 10;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledMedium1)
    {
        size_t sender_size = 500;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledMedium2)
    {
        size_t sender_size = 500;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledMediumMultiThreaded1)
    {
        size_t sender_size = 500;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledMediumMultiThreaded2)
    {
        size_t sender_size = 500;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledLarge1)
    {
        size_t sender_size = 4000;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledLarge2)
    {
        size_t sender_size = 4000;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledLargeMultiThreaded1)
    {
        size_t sender_size = 4000;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledLargeMultiThreaded2)
    {
        size_t sender_size = 4000;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledHugeMultiThreaded1)
    {
        size_t sender_size = 50000;
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
            create_huge_params1(),
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledHugeMultiThreaded2)
    {
        size_t sender_size = 50000;
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
            create_huge_params2(),
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledEmpty1)
    {
        size_t sender_size = 0;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), 1);
    }

    TEST(StreamSenderReceiverTests, LabeledEmpty2)
    {
        size_t sender_size = 0;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), 1);
    }

    TEST(StreamSenderReceiverTests, LabeledEmptyMultiThreaded1)
    {
        size_t sender_size = 0;
        RunLabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, create_params1(), thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledEmptyMultiThreaded2)
    {
        size_t sender_size = 0;
        RunLabeledTest(
            sender_size, { { 0, 0 }, { 1, 0 } }, create_params2(), thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledSingle1)
    {
        size_t sender_size = 1;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params1(), 1);
    }

    TEST(StreamSenderReceiverTests, LabeledSingle2)
    {
        size_t sender_size = 1;
        RunLabeledTest(sender_size, { { 0, 0 }, { 1, 0 }, { 1, 1 } }, create_params2(), 1);
    }

    TEST(StreamSenderReceiverTests, LabeledSingleMultiThreaded1)
    {
        size_t sender_size = 1;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledSingleMultiThreaded2)
    {
        size_t sender_size = 1;
        RunLabeledTest(
            sender_size,
            { { 0, 0 }, { 1, 0 }, { 1, 1 } },
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledSmall1)
    {
        size_t sender_size = 10;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledSmall2)
    {
        size_t sender_size = 10;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledSmallMultiThreaded1)
    {
        size_t sender_size = 10;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledSmallMultiThreaded2)
    {
        size_t sender_size = 10;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledMedium1)
    {
        size_t sender_size = 500;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledMedium2)
    {
        size_t sender_size = 500;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledMediumMultiThreaded1)
    {
        size_t sender_size = 500;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledMediumMultiThreaded2)
    {
        size_t sender_size = 500;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledLarge1)
    {
        size_t sender_size = 4000;
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
            create_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledLarge2)
    {
        size_t sender_size = 4000;
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
            create_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledLargeMultiThreaded1)
    {
        size_t sender_size = 4000;
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
            create_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledLargeMultiThreaded2)
    {
        size_t sender_size = 4000;
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
            create_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledHugeMultiThreaded1)
    {
        size_t sender_size = 50000;
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
            create_huge_params1(),
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledHugeMultiThreaded2)
    {
        size_t sender_size = 50000;
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
            create_huge_params2(),
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params2(),
            thread::hardware_concurrency());
    }
} // namespace APSITests
