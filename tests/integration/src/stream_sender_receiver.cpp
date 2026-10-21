// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

// APSI
#include "apsi/log.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/db_encoding.h"
#include "test_utils.h"

// Kuku
#include "kuku/locfunc.h"

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
            const vector<pair<size_t, size_t>> &client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads)
        {
            // Install a null sink but keep the level at info, so log calls still format their
            // messages and run through the logger's locking/dispatch (exercised by the
            // multithreaded handshake below) while the empty handlers discard the output.
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(num_threads);

            vector<Item> sender_items;
            sender_items.reserve(sender_size);
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(i + 1, i + 1);
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
                recv_items.reserve(recv_int_items.size());
                for (auto item : recv_int_items) {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++) {
                    recv_items.emplace_back(i + 1, ~(i + 1));
                }

                // Create the OPRF receiver
                oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
                Request oprf_request = Receiver::CreateOPRFRequest(oprf_receiver);

                // Send the OPRF request
                ASSERT_NO_THROW(chl.send(std::move(oprf_request)));
                size_t bytes_sent = chl.bytes_sent();

                // Receive the OPRF request and process response
                OPRFRequest oprf_request2 =
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
                size_t bytes_received = chl.bytes_received();
                ASSERT_EQ(bytes_sent, bytes_received);
                ASSERT_NO_THROW(Sender::RunOPRF(oprf_request2, oprf_key, chl));

                // Receive OPRF response
                OPRFResponse oprf_response = to_oprf_response(chl.receive_response());

                auto [hashed_recv_items, label_keys] =
                    Receiver::ExtractHashes(oprf_response, oprf_receiver);
                ASSERT_EQ(hashed_recv_items.size(), recv_items.size());

                // Create query and send
                pair<Request, IndexTranslationTable> recv_query_pair =
                    receiver.create_query(hashed_recv_items);

                QueryRequest recv_query = to_query_request(std::move(recv_query_pair.first));
                compr_mode_type expected_compr_mode = recv_query->compr_mode;

                IndexTranslationTable itt = std::move(recv_query_pair.second);
                chl.send(std::move(recv_query));

                // Receive the query and process response
                QueryRequest sender_query = to_query_request(chl.receive_operation(seal_context));
                Query query(std::move(sender_query), sender_db);
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
            const vector<pair<size_t, size_t>> &client_total_and_int_sizes,
            const PSIParams &params,
            size_t num_threads)
        {
            // Install a null sink but keep the level at info, so log calls still format their
            // messages and run through the logger's locking/dispatch (exercised by the
            // multithreaded handshake below) while the empty handlers discard the output.
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(num_threads);

            vector<pair<Item, Label>> sender_items;
            sender_items.reserve(sender_size);
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(
                    Item(i + 1, i + 1),
                    create_label(seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), 10));
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
                recv_items.reserve(recv_int_items.size());
                for (auto item : recv_int_items) {
                    recv_items.push_back(item);
                }
                for (size_t i = int_size; i < client_size; i++) {
                    recv_items.emplace_back(i + 1, ~(i + 1));
                }

                // Create the OPRF receiver
                oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
                Request oprf_request = Receiver::CreateOPRFRequest(oprf_receiver);

                // Send the OPRF request
                ASSERT_NO_THROW(chl.send(std::move(oprf_request)));
                size_t bytes_sent = chl.bytes_sent();

                // Receive the OPRF request and process response
                OPRFRequest oprf_request2 =
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
                size_t bytes_received = chl.bytes_received();
                ASSERT_EQ(bytes_sent, bytes_received);
                ASSERT_NO_THROW(Sender::RunOPRF(oprf_request2, oprf_key, chl));

                // Receive OPRF response
                OPRFResponse oprf_response = to_oprf_response(chl.receive_response());

                auto [hashed_recv_items, label_keys] =
                    Receiver::ExtractHashes(oprf_response, oprf_receiver);
                ASSERT_EQ(hashed_recv_items.size(), recv_items.size());

                // Create query and send
                pair<Request, IndexTranslationTable> recv_query =
                    receiver.create_query(hashed_recv_items);
                IndexTranslationTable itt = std::move(recv_query.second);
                chl.send(std::move(recv_query.first));

                // Receive the query and process response
                QueryRequest sender_query = to_query_request(chl.receive_operation(seal_context));
                Query query(std::move(sender_query), sender_db);
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

        /**
        Runs one query through the whole protocol on a StreamChannel and returns its result. The
        OPRF key is given separately, as a stripped SenderDB no longer holds it.
        */
        vector<MatchRecord> RunQuery(
            const shared_ptr<SenderDB> &sender_db,
            const oprf::OPRFKey &oprf_key,
            Receiver &receiver,
            const PSIParams &params,
            const vector<Item> &recv_items,
            StreamChannel &chl)
        {
            oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
            chl.send(Receiver::CreateOPRFRequest(oprf_receiver));
            OPRFRequest oprf_request =
                to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
            Sender::RunOPRF(oprf_request, oprf_key, chl);
            OPRFResponse oprf_response = to_oprf_response(chl.receive_response());
            auto [hashed_recv_items, label_keys] =
                Receiver::ExtractHashes(oprf_response, oprf_receiver);

            auto query = receiver.create_query(hashed_recv_items);
            IndexTranslationTable itt = std::move(query.second);
            chl.send(std::move(query.first));
            QueryRequest sender_query =
                to_query_request(chl.receive_operation(sender_db->get_seal_context()));
            Query sender_side_query(std::move(sender_query), sender_db);
            Sender::RunQuery(sender_side_query, chl);

            QueryResponse query_response = to_query_response(chl.receive_response());
            uint32_t package_count = query_response->package_count;
            vector<ResultPart> rps;
            while (package_count--) {
                rps.push_back(chl.receive_result_for(receiver.get_seal_context(), params));
            }
            return receiver.process_result(label_keys, itt, rps);
        }

        /**
        Runs queries against parameters with match tags and only 13 bits per item, where some of
        the sender's items share their bin and field element with another and so sit in different
        bin bundles at the same place. The queries hold exactly those items, and items of the
        receiver's own that share their bin and field element with one of the sender's: such an
        item is answered with the tag of the sender's item, and must still not match.

        Which items share their place depends on the OPRF key, so the key is fixed. Of 20000
        items, about 24 share their place with another on average, and fewer than the 10 asked
        for below about once in a hundred random keys; with the fixed key, 26 do.
        */
        void RunTagCollisionTest(size_t sender_size, size_t label_byte_count, size_t num_threads)
        {
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(num_threads);

            PSIParams params = create_tag_collision_params();
            oprf::OPRFKey oprf_key = fixed_oprf_key();
            auto sender_db = make_shared<SenderDB>(params, oprf_key, label_byte_count, 4, true);

            vector<Item> sender_items;
            vector<pair<Item, Label>> sender_item_labels;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(i + 1, i + 1);
                sender_item_labels.emplace_back(
                    sender_items.back(),
                    create_label(
                        seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), label_byte_count));
            }
            if (label_byte_count) {
                sender_db->set_data(sender_item_labels);
            } else {
                sender_db->set_data(sender_items);
            }

            // Where each item goes: its bin, given by its one hash function, and its one field
            // element
            kuku::LocFunc hash_func(params.table_params().table_size, kuku::make_item(0, 0));
            auto place = [&](const HashedItem &hashed_item) {
                kuku::item_type kuku_item;
                memcpy(&kuku_item, hashed_item.value().data(), sizeof(kuku_item));
                felt_t felt = algebraize_item(
                    hashed_item, params.item_bit_count(), params.seal_params().plain_modulus())[0];
                return make_pair(hash_func(kuku_item), felt);
            };

            vector<HashedItem> sender_hashes = OPRFSender::ComputeHashes(sender_items, oprf_key);
            map<pair<uint32_t, felt_t>, vector<size_t>> places;
            for (size_t i = 0; i < sender_size; i++) {
                places[place(sender_hashes[i])].push_back(i);
            }

            // The sender's items that share their place with another
            vector<Item> colliding_items;
            for (const auto &p : places) {
                if (p.second.size() > 1) {
                    for (size_t i : p.second) {
                        colliding_items.push_back(sender_items[i]);
                    }
                }
            }
            ASSERT_LE(size_t(10), colliding_items.size());
            ASSERT_LE(size_t(2), sender_db->get_bin_bundle_count(0));

            // Items that are not the sender's but share a place with one of the sender's
            vector<Item> candidates;
            for (uint64_t i = 0; i < 100000; i++) {
                candidates.emplace_back(i + 1, ~(i + 1));
            }
            vector<HashedItem> candidate_hashes = OPRFSender::ComputeHashes(candidates, oprf_key);
            vector<Item> impostors;
            for (size_t i = 0; i < candidates.size() && impostors.size() < 40; i++) {
                if (places.count(place(candidate_hashes[i]))) {
                    impostors.push_back(candidates[i]);
                }
            }
            ASSERT_LE(size_t(10), impostors.size());

            // The receiver's cuckoo table has one hash function, so a query can hold only one
            // item for each bin. Spread the items over as many queries as that takes.
            vector<vector<Item>> batches;
            vector<set<uint32_t>> batch_bins;
            auto add_to_batch = [&](const Item &item, const HashedItem &hashed_item) {
                uint32_t bin = place(hashed_item).first;
                size_t batch_idx = 0;
                while (batch_idx < batches.size() && batch_bins[batch_idx].count(bin)) {
                    batch_idx++;
                }
                if (batch_idx == batches.size()) {
                    batches.emplace_back();
                    batch_bins.emplace_back();
                }
                batches[batch_idx].push_back(item);
                batch_bins[batch_idx].insert(bin);
            };
            vector<HashedItem> colliding_hashes =
                OPRFSender::ComputeHashes(colliding_items, oprf_key);
            for (size_t i = 0; i < colliding_items.size(); i++) {
                add_to_batch(colliding_items[i], colliding_hashes[i]);
            }
            vector<HashedItem> impostor_hashes = OPRFSender::ComputeHashes(impostors, oprf_key);
            for (size_t i = 0; i < impostors.size(); i++) {
                add_to_batch(impostors[i], impostor_hashes[i]);
            }
            ASSERT_LE(size_t(2), batches.size());

            stringstream ss;
            StreamChannel chl(ss);
            Receiver receiver(params);

            unordered_set<Item> colliding_set(colliding_items.begin(), colliding_items.end());
            for (const auto &recv_items : batches) {
                vector<Item> int_items;
                for (const auto &item : recv_items) {
                    if (colliding_set.count(item)) {
                        int_items.push_back(item);
                    }
                }

                vector<MatchRecord> query_result =
                    RunQuery(sender_db, oprf_key, receiver, params, recv_items, chl);
                if (label_byte_count) {
                    verify_labeled_results(query_result, recv_items, int_items, sender_item_labels);
                } else {
                    verify_unlabeled_results(query_result, recv_items, int_items);
                }
            }
        }

        /**
        Runs queries against a SenderDB with match tags that has been stripped, saved and loaded,
        as a deployment would serve one.
        */
        void RunTagStrippedTest(
            const PSIParams &params,
            size_t sender_size,
            size_t label_byte_count,
            const vector<pair<size_t, size_t>> &client_total_and_int_sizes)
        {
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            ThreadPoolMgr::SetThreadCount(thread::hardware_concurrency());

            vector<Item> sender_items;
            vector<pair<Item, Label>> sender_item_labels;
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(i + 1, i + 1);
                sender_item_labels.emplace_back(
                    sender_items.back(),
                    create_label(
                        seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), label_byte_count));
            }

            SenderDB built(params, label_byte_count, 16, true);
            if (label_byte_count) {
                built.set_data(sender_item_labels);
            } else {
                built.set_data(sender_items);
            }
            oprf::OPRFKey oprf_key = built.strip();
            stringstream db_stream;
            built.save(db_stream);
            auto sender_db = make_shared<SenderDB>(SenderDB::Load(db_stream).first);
            ASSERT_TRUE(sender_db->is_stripped());

            stringstream ss;
            StreamChannel chl(ss);
            Receiver receiver(params);

            for (const auto &client_total_and_int_size : client_total_and_int_sizes) {
                size_t client_size = client_total_and_int_size.first;
                size_t int_size = client_total_and_int_size.second;

                vector<Item> recv_int_items = rand_subset(sender_items, int_size);
                vector<Item> recv_items = recv_int_items;
                for (size_t i = int_size; i < client_size; i++) {
                    recv_items.emplace_back(i + 1, ~(i + 1));
                }

                vector<MatchRecord> query_result =
                    RunQuery(sender_db, oprf_key, receiver, params, recv_items, chl);
                if (label_byte_count) {
                    verify_labeled_results(
                        query_result, recv_items, recv_int_items, sender_item_labels);
                } else {
                    verify_unlabeled_results(query_result, recv_items, recv_int_items);
                }
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
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmall2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledSmallMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledMedium1)
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
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledMedium2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, UnlabeledMediumMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, UnlabeledMediumMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledLarge1)
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
            1);
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledLarge2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledLargeMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledHugeMultiThreaded1)
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
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunUnlabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_UnlabeledHugeMultiThreaded2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledSmall2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledSmallMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledSmallMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledMedium1)
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
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledMedium2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, LabeledMediumMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, LabeledMediumMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledLarge1)
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
            1);
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledLarge2)
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
            1);
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledLargeMultiThreaded1)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledLargeMultiThreaded2)
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
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledHugeMultiThreaded1)
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
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, DISABLED_LabeledHugeMultiThreaded2)
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
            thread::hardware_concurrency());

        sender_size = 1'000'000;
        RunLabeledTest(
            sender_size,
            { { 10000, 10000 } },
            create_huge_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, TagUnlabeled1)
    {
        RunUnlabeledTest(
            1000,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 10, 0 }, { 10, 5 }, { 100, 50 }, { 100, 100 } },
            create_tag_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, TagUnlabeledMultiThreaded1)
    {
        RunUnlabeledTest(
            5000,
            { { 1, 0 }, { 1, 1 }, { 10, 10 }, { 100, 1 }, { 100, 99 } },
            create_tag_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, TagUnlabeled2)
    {
        RunUnlabeledTest(
            1000,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 10, 5 }, { 100, 50 }, { 100, 100 } },
            create_tag_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, TagUnlabeledMultiThreaded2)
    {
        RunUnlabeledTest(
            5000,
            { { 1, 1 }, { 10, 3 }, { 100, 100 } },
            create_tag_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, TagLabeled1)
    {
        RunLabeledTest(
            1000,
            { { 0, 0 }, { 1, 0 }, { 1, 1 }, { 10, 5 }, { 100, 50 }, { 100, 100 } },
            create_tag_params1(),
            1);
    }

    TEST(StreamSenderReceiverTests, TagLabeledMultiThreaded1)
    {
        RunLabeledTest(
            5000,
            { { 1, 1 }, { 10, 10 }, { 100, 1 }, { 100, 100 } },
            create_tag_params1(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, TagLabeled2)
    {
        RunLabeledTest(
            1000,
            { { 0, 0 }, { 1, 1 }, { 10, 5 }, { 100, 50 }, { 100, 100 } },
            create_tag_params2(),
            1);
    }

    TEST(StreamSenderReceiverTests, TagLabeledMultiThreaded2)
    {
        RunLabeledTest(
            5000,
            { { 1, 0 }, { 10, 10 }, { 100, 100 } },
            create_tag_params2(),
            thread::hardware_concurrency());
    }

    TEST(StreamSenderReceiverTests, TagStrippedUnlabeled)
    {
        RunTagStrippedTest(create_tag_params2(), 2000, 0, { { 1, 1 }, { 10, 4 }, { 100, 30 } });
    }

    TEST(StreamSenderReceiverTests, TagStrippedLabeled)
    {
        RunTagStrippedTest(create_tag_params1(), 2000, 20, { { 1, 1 }, { 10, 4 }, { 100, 30 } });
    }

    TEST(StreamSenderReceiverTests, TagCollisionsUnlabeled)
    {
        RunTagCollisionTest(20000, 0, 1);
    }

    TEST(StreamSenderReceiverTests, TagCollisionsLabeledMultiThreaded)
    {
        RunTagCollisionTest(20000, 12, thread::hardware_concurrency());
    }
} // namespace APSITests
