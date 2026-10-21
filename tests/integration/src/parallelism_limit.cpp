// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_receiver.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
#include "test_utils.h"

// SEAL
#include "seal/modulus.h"
#include "seal/util/common.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::network;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal;

namespace APSITests {
    namespace {
        /**
        Parameters with small bins, so that a SenderDB of a few thousand items has several bin
        bundles at each bundle index, and a query several result packages to compute.
        */
        PSIParams create_small_bin_params()
        {
            PSIParams::ItemParams item_params;
            item_params.felts_per_item = 8;

            PSIParams::TableParams table_params;
            table_params.hash_func_count = 3;
            table_params.max_items_per_bin = 6;
            table_params.table_size = 4096;

            PSIParams::QueryParams query_params;
            query_params.query_powers = { 1, 3 };

            PSIParams::SEALParams seal_params;
            seal_params.set_poly_modulus_degree(8192);
            seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
            seal_params.set_plain_modulus(65537);

            return { item_params, table_params, query_params, seal_params };
        }

        /**
        A receiver's query against a SenderDB, made once: the OPRF request and the query as the
        bytes a sender receives, and what the receiver needs to read the answer. Every run
        answers exactly these bytes.
        */
        struct PreparedQuery {
            PreparedQuery(shared_ptr<SenderDB> db, oprf::OPRFKey key)
                : sender_db(std::move(db)), oprf_key(std::move(key)),
                  params(sender_db->get_params()), receiver(params)
            {}

            shared_ptr<SenderDB> sender_db;

            oprf::OPRFKey oprf_key;

            PSIParams params;

            Receiver receiver;

            string oprf_request;

            string query;

            LabelKeyVector label_keys;

            optional<IndexTranslationTable> itt;
        };

        /**
        A sender's answer to a PreparedQuery: the OPRF response and the result packages as bytes,
        the packages sorted, since they are sent in the order they are computed in, and the
        matches the receiver reads from them.
        */
        struct Answer {
            string oprf_response;

            uint32_t package_count = 0;

            vector<string> packages;

            vector<MatchRecord> matches;
        };

        /**
        Answers a query as a sender does, on the calling thread under the given limit, and reads
        the answer as the receiver does.
        */
        Answer AnswerQuery(const PreparedQuery &pq, size_t limit)
        {
            ScopedParallelismLimit scope(limit);
            Answer answer;

            {
                stringstream in(pq.oprf_request);
                stringstream out;
                StreamChannel chl(in, out);
                Sender::RunOPRF(
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf)),
                    pq.oprf_key,
                    chl);
                answer.oprf_response = out.str();
            }

            stringstream in(pq.query);
            stringstream out;
            StreamChannel chl(in, out);
            Query query(
                to_query_request(chl.receive_operation(pq.sender_db->get_seal_context())),
                pq.sender_db);

            mutex packages_mutex;
            Sender::RunQuery(
                query,
                chl,
                [](Channel &c, Response response) { c.send(std::move(response)); },
                [&](Channel &c, ResultPart rp) {
                    stringstream bytes;
                    rp->save(bytes);
                    {
                        lock_guard<mutex> lock(packages_mutex);
                        answer.packages.push_back(bytes.str());
                    }
                    c.send(std::move(rp));
                });
            sort(answer.packages.begin(), answer.packages.end());

            stringstream back(out.str());
            StreamChannel receiver_chl(back);
            QueryResponse response = to_query_response(receiver_chl.receive_response());
            answer.package_count = response->package_count;
            vector<ResultPart> rps;
            for (uint32_t i = 0; i < answer.package_count; i++) {
                rps.push_back(
                    receiver_chl.receive_result_for(pq.receiver.get_seal_context(), pq.params));
            }
            answer.matches = pq.receiver.process_result(pq.label_keys, *pq.itt, rps);

            return answer;
        }

        /**
        Makes a query for the given items. The receiver reads the OPRF response of a run without
        a limit.
        */
        unique_ptr<PreparedQuery> Prepare(
            shared_ptr<SenderDB> sender_db, oprf::OPRFKey oprf_key, const vector<Item> &items)
        {
            auto pq = make_unique<PreparedQuery>(std::move(sender_db), std::move(oprf_key));

            oprf::OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(items);
            {
                stringstream ss;
                StreamChannel chl(ss);
                chl.send(Receiver::CreateOPRFRequest(oprf_receiver));
                pq->oprf_request = ss.str();
            }

            OPRFResponse oprf_response;
            {
                stringstream in(pq->oprf_request);
                stringstream out;
                StreamChannel chl(in, out);
                Sender::RunOPRF(
                    to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf)),
                    pq->oprf_key,
                    chl);
                stringstream back(out.str());
                StreamChannel receiver_chl(back);
                oprf_response = to_oprf_response(receiver_chl.receive_response());
            }
            auto hashes = Receiver::ExtractHashes(oprf_response, oprf_receiver);
            pq->label_keys = std::move(hashes.second);

            auto query = pq->receiver.create_query(hashes.first);
            pq->itt.emplace(std::move(query.second));
            {
                stringstream ss;
                StreamChannel chl(ss);
                chl.send(std::move(query.first));
                pq->query = ss.str();
            }

            return pq;
        }

        void ExpectSameAnswer(const Answer &expected, const Answer &actual)
        {
            // Compared without printing: the bytes run to megabytes.
            EXPECT_TRUE(expected.oprf_response == actual.oprf_response);
            EXPECT_EQ(expected.package_count, actual.package_count);
            EXPECT_EQ(expected.packages.size(), actual.packages.size());
            EXPECT_TRUE(expected.packages == actual.packages);
            ASSERT_EQ(expected.matches.size(), actual.matches.size());
            for (size_t i = 0; i < expected.matches.size(); i++) {
                EXPECT_EQ(expected.matches[i].found, actual.matches[i].found);
                EXPECT_TRUE(expected.matches[i].label.value() == actual.matches[i].label.value());
            }
        }

        /**
        Items to query: the given items of the sender's, followed by other_count that the sender
        does not hold.
        */
        vector<Item> query_items(const vector<Item> &int_items, size_t other_count)
        {
            vector<Item> items = int_items;
            for (size_t i = 0; i < other_count; i++) {
                items.emplace_back(i + 1, ~(i + 1));
            }
            return items;
        }

        string saved(const SenderDB &sender_db)
        {
            stringstream ss;
            sender_db.save(ss);
            return ss.str();
        }
    } // namespace

    TEST(ParallelismLimitTests, ConcurrentQueriesAnswerAsWithoutALimit)
    {
        // Two senders answer at once, each on its own thread under its own limit. Every answer
        // must be exactly the one given without a limit: the same OPRF response, and the same
        // result packages, byte for byte, in whatever order they are computed in.
        SetLogger(Logger::Create({}, {}, {}));
        SetLogLevel(LogLevel::info);
        ThreadPoolMgr::SetThreadCount(4);
        ThreadPoolMgr::SetPoolWorkerCount(8);

        // Held throughout, as a server holds the pool while it serves
        ThreadPoolMgr tpm;

        constexpr size_t sender_size = 4000;
        vector<Item> sender_items;
        vector<pair<Item, Label>> sender_item_labels;
        for (size_t i = 0; i < sender_size; i++) {
            sender_items.emplace_back(i + 1, i + 1);
            sender_item_labels.emplace_back(
                sender_items.back(),
                create_label(seal::util::safe_cast<unsigned char>((i + 1) & 0xFF), 10));
        }

        // A labeled sender with matching polynomials, and an unlabeled one with match tags
        auto labeled_db = make_shared<SenderDB>(create_small_bin_params(), 10, 4, true);
        labeled_db->set_data(sender_item_labels);
        auto tagged_db = make_shared<SenderDB>(create_tag_params1(), 0, 16, true);
        tagged_db->set_data(sender_items);

        const vector<Item> labeled_int = rand_subset(sender_item_labels, 10);
        const vector<Item> labeled_items = query_items(labeled_int, 10);
        const vector<Item> tagged_int = rand_subset(sender_items, 10);
        const vector<Item> tagged_items = query_items(tagged_int, 10);
        auto labeled = Prepare(labeled_db, labeled_db->get_oprf_key(), labeled_items);
        auto tagged = Prepare(tagged_db, tagged_db->get_oprf_key(), tagged_items);

        const Answer labeled_expected = AnswerQuery(*labeled, 0);
        const Answer tagged_expected = AnswerQuery(*tagged, 0);
        verify_labeled_results(
            labeled_expected.matches, labeled_items, labeled_int, sender_item_labels);
        verify_unlabeled_results(tagged_expected.matches, tagged_items, tagged_int);

        // Enough result packages that a limit of 4 queues some of them
        ASSERT_LT(size_t(4), labeled_expected.packages.size());

        const vector<pair<size_t, size_t>> limits = { { 1, 1 }, { 4, 4 }, { 1, 4 }, { 4, 0 } };
        for (const auto &limit : limits) {
            SCOPED_TRACE("limits " + to_string(limit.first) + " and " + to_string(limit.second));
            auto labeled_answer = async(launch::async, AnswerQuery, cref(*labeled), limit.first);
            auto tagged_answer = async(launch::async, AnswerQuery, cref(*tagged), limit.second);
            ExpectSameAnswer(labeled_expected, labeled_answer.get());
            ExpectSameAnswer(tagged_expected, tagged_answer.get());
        }

        ThreadPoolMgr::SetThreadCount(0);
    }

    TEST(ParallelismLimitTests, InsertLoadAndStripAsWithoutALimit)
    {
        // Under a limit, building and updating a SenderDB give exactly the bytes they give
        // without one, a loaded SenderDB answers exactly as the one saved, and stripping gives
        // the same bytes and the same answers.
        SetLogger(Logger::Create({}, {}, {}));
        SetLogLevel(LogLevel::info);
        ThreadPoolMgr::SetThreadCount(4);
        ThreadPoolMgr::SetPoolWorkerCount(8);
        ThreadPoolMgr tpm;

        const PSIParams params = create_small_bin_params();
        const oprf::OPRFKey oprf_key = fixed_oprf_key();
        vector<Item> initial_items;
        vector<Item> inserted_items;
        vector<Item> removed_items;
        for (size_t i = 0; i < 3000; i++) {
            initial_items.emplace_back(i + 1, i + 1);
            if (i % 10 == 0) {
                removed_items.push_back(initial_items.back());
            }
        }
        for (size_t i = 3000; i < 3500; i++) {
            inserted_items.emplace_back(i + 1, i + 1);
        }

        auto build = [&](size_t limit) {
            ScopedParallelismLimit scope(limit);
            auto sender_db = make_shared<SenderDB>(params, oprf_key);
            sender_db->set_data(initial_items);
            sender_db->insert_or_assign(inserted_items);
            sender_db->remove(removed_items);
            return sender_db;
        };
        auto strip = [](const shared_ptr<SenderDB> &sender_db, size_t limit) {
            ScopedParallelismLimit scope(limit);
            sender_db->strip();
        };

        const auto unlimited = build(0);
        const string unlimited_bytes = saved(*unlimited);

        // Two items set at first, one inserted later, and one removed, which must not match
        const vector<Item> int_items = { initial_items[1], initial_items[2], inserted_items[0] };
        vector<Item> items = query_items(int_items, 6);
        items.push_back(removed_items[0]);
        auto pq = Prepare(unlimited, oprf_key, items);

        const Answer expected = AnswerQuery(*pq, 0);
        verify_unlabeled_results(expected.matches, items, int_items);

        const auto stripped_unlimited = build(0);
        strip(stripped_unlimited, 0);
        const string stripped_bytes = saved(*stripped_unlimited);

        for (size_t limit : { size_t(1), size_t(3) }) {
            SCOPED_TRACE("limit " + to_string(limit));

            EXPECT_TRUE(saved(*build(limit)) == unlimited_bytes);

            {
                stringstream ss(unlimited_bytes);
                ScopedParallelismLimit scope(limit);
                pq->sender_db = make_shared<SenderDB>(SenderDB::Load(ss).first);
            }
            ExpectSameAnswer(expected, AnswerQuery(*pq, limit));

            const auto stripped = build(0);
            strip(stripped, limit);
            EXPECT_TRUE(saved(*stripped) == stripped_bytes);
            pq->sender_db = stripped;
            ExpectSameAnswer(expected, AnswerQuery(*pq, limit));
        }

        ThreadPoolMgr::SetThreadCount(0);
    }
} // namespace APSITests
