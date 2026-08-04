// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/network/network_channel.h"
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/stream_channel.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/receiver.h"
#include "apsi/sender.h"
#include "apsi/sender_db.h"
#include "apsi/thread_pool_mgr.h"
#include "seal/util/common.h"
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
        Hands Receiver::request_query a fixed, caller-supplied script of result packages,
        modelling a sender that answers a query with whatever it likes.

        Deriving from NetworkChannel rather than reusing StreamChannel is forced:
        request_query only accepts a network::NetworkChannel, NetworkChannel is an empty
        marker class deriving from Channel, and StreamChannel derives from Channel directly.
        It is also the more precise tool, because it lets a test hand out exactly the
        packages it wants in exactly the order it wants.

        receive_result must not return nullptr while workers still expect packages: the
        worker loop spins on a null result, so the script has to hold exactly as many
        packages as the announced package_count.
        */
        class ReplayChannel final : public NetworkChannel {
        public:
            explicit ReplayChannel(vector<ResultPackage> script) : script_(std::move(script))
            {}

            void send(unique_ptr<SenderOperation>) override
            {
                // The query is discarded. This channel replays a canned script instead of
                // computing an answer.
            }

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                auto response = make_unique<SenderOperationResponseQuery>();
                response->package_count = static_cast<uint32_t>(script_.size());
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                lock_guard<mutex> lock(mtx_);
                if (next_ >= script_.size()) {
                    return nullptr;
                }
                return make_unique<ResultPackage>(script_[next_++]);
            }

        private:
            mutex mtx_;

            vector<ResultPackage> script_;

            size_t next_ = 0;
        }; // class ReplayChannel

        /**
        Everything an honest query produced, kept so that a hostile script can be built from
        genuine material. Replayed honest packages are well formed and correctly encrypted,
        so they are exactly what a malicious sender can send without any forgery.
        */
        struct HonestQuery {
            vector<Item> recv_items;

            vector<Item> recv_int_items;

            vector<HashedItem> hashed_recv_items;

            LabelKeyVector label_keys;

            // IndexTranslationTable has no public default constructor, which is why this
            // struct is only ever built by aggregate initialization at the end of
            // RunHonestQuery rather than filled in field by field.
            IndexTranslationTable itt;

            vector<ResultPackage> packages;

            // Empty for an unlabeled run. verify_labeled_results needs the sender's full
            // item -> label map, so a labeled run has to carry it along.
            vector<pair<Item, Label>> sender_item_labels;
        }; // struct HonestQuery

        /**
        Checks a query result against the honest expectation, picking the right verifier for the
        labeled and unlabeled cases.
        */
        void VerifyResults(const HonestQuery &honest, const vector<MatchRecord> &query_result)
        {
            if (honest.sender_item_labels.empty()) {
                verify_unlabeled_results(query_result, honest.recv_items, honest.recv_int_items);
            } else {
                verify_labeled_results(
                    query_result,
                    honest.recv_items,
                    honest.recv_int_items,
                    honest.sender_item_labels);
            }
        }

        /**
        Runs one complete, honest query over a StreamChannel and captures the sender's result
        packages. The receiver is passed in because the packages are encrypted under its keys
        and must be replayed to that same instance.
        */
        HonestQuery RunHonestQuery(
            Receiver &receiver,
            const PSIParams &params,
            size_t sender_size,
            size_t client_size,
            size_t int_size,
            size_t label_byte_count = 0)
        {
            vector<Item> sender_items;
            sender_items.reserve(sender_size);
            for (size_t i = 0; i < sender_size; i++) {
                sender_items.emplace_back(i + 1, i + 1);
            }

            // A labeled sender is what puts real memory at stake. A MatchRecord for a labeled
            // query owns a heap-allocated Label buffer, whereas an unlabeled one carries an
            // empty vector, so only the labeled case exercises ownership of live storage.
            vector<pair<Item, Label>> sender_item_labels;
            shared_ptr<SenderDB> sender_db;
            if (label_byte_count) {
                sender_item_labels.reserve(sender_size);
                for (size_t i = 0; i < sender_size; i++) {
                    sender_item_labels.emplace_back(
                        sender_items[i],
                        create_label(
                            seal::util::safe_cast<unsigned char>((i + 1) & 0xFF),
                            label_byte_count));
                }
                sender_db = make_shared<SenderDB>(params, label_byte_count, 4, true);
                sender_db->set_data(sender_item_labels);
            } else {
                sender_db = make_shared<SenderDB>(params, 0);
                sender_db->set_data(sender_items);
            }
            auto oprf_key = sender_db->get_oprf_key();
            auto seal_context = sender_db->get_seal_context();

            vector<Item> recv_int_items = rand_subset(sender_items, int_size);
            vector<Item> recv_items = recv_int_items;
            for (size_t i = int_size; i < client_size; i++) {
                recv_items.emplace_back(i + 1, ~(i + 1));
            }

            stringstream ss;
            StreamChannel chl(ss);

            OPRFReceiver oprf_receiver = Receiver::CreateOPRFReceiver(recv_items);
            chl.send(Receiver::CreateOPRFRequest(oprf_receiver));
            OPRFRequest oprf_request =
                to_oprf_request(chl.receive_operation(nullptr, SenderOperationType::sop_oprf));
            Sender::RunOPRF(oprf_request, oprf_key, chl);
            OPRFResponse oprf_response = to_oprf_response(chl.receive_response());

            vector<HashedItem> hashed_recv_items;
            LabelKeyVector label_keys;
            tie(hashed_recv_items, label_keys) =
                Receiver::ExtractHashes(oprf_response, oprf_receiver);

            auto recv_query_pair = receiver.create_query(hashed_recv_items);
            IndexTranslationTable itt = std::move(recv_query_pair.second);
            chl.send(std::move(recv_query_pair.first));

            Query query(to_query_request(chl.receive_operation(seal_context)), sender_db);
            Sender::RunQuery(query, chl);

            QueryResponse query_response = to_query_response(chl.receive_response());
            uint32_t package_count = query_response->package_count;

            vector<ResultPart> rps;
            while (package_count--) {
                rps.push_back(chl.receive_result(receiver.get_seal_context()));
            }

            // Copy the packages out before the baseline check below, because processing a
            // result part extracts (and thereby consumes) the ciphertexts inside it.
            vector<ResultPackage> packages;
            packages.reserve(rps.size());
            for (const auto &rp : rps) {
                packages.push_back(*rp);
            }

            HonestQuery result{ std::move(recv_items),
                                std::move(recv_int_items),
                                std::move(hashed_recv_items),
                                std::move(label_keys),
                                std::move(itt),
                                std::move(packages),
                                std::move(sender_item_labels) };

            // Confirm the captured material really is a correct answer, so that a later
            // failure points at the hostile behaviour and not at a broken capture.
            VerifyResults(result, receiver.process_result(result.label_keys, result.itt, rps));

            return result;
        }

        void SetUpTestLoggingAndThreads()
        {
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            size_t num_threads = thread::hardware_concurrency();
            ThreadPoolMgr::SetThreadCount(num_threads);

            // Give the pool more workers than the query fans out to, so the result workers
            // genuinely run at the same time instead of being serialized behind each other.
            ThreadPoolMgr::SetPoolWorkerCount(num_threads * 2);
        }
    } // namespace

    TEST(HostileSenderTests, DuplicateResultPackagesAreIgnored)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // More than one package is what makes the concurrent path interesting.
        ASSERT_LE(size_t(2), honest.packages.size());

        // A malicious sender replays every package twice, announcing twice the package
        // count. Each duplicate is adjacent to its original so that two workers pick the
        // pair up at nearly the same instant, which puts them on the same MatchRecord slot
        // concurrently. The receiver must resolve that collision without racing and without
        // letting one hostile package destroy an otherwise valid answer.
        vector<ResultPackage> script;
        script.reserve(honest.packages.size() * 2);
        for (const auto &rp : honest.packages) {
            script.push_back(rp);
            script.push_back(rp);
        }

        ReplayChannel chl(std::move(script));
        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(
            query_result =
                receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl));

        // The duplicates must be dropped, not merged: the answer is exactly the honest one.
        VerifyResults(honest, query_result);
    }

    TEST(HostileSenderTests, LabeledDuplicateResultPackagesAreIgnored)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);

        // The labeled variant of DuplicateResultPackagesAreIgnored, and the one that carries the
        // real memory-safety weight. A MatchRecord holds a LabelData wrapping a
        // std::vector<unsigned char>, which for a labeled query owns a heap allocation. Two
        // workers reaching the same slot must therefore be serialized: unsynchronized
        // move-assignment would have both destroy the destination's buffer and both install
        // their own, which is a double free. An unlabeled query cannot show this, because its
        // Label vector is empty and holds nothing to release.
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10, 10);
        ASSERT_LE(size_t(2), honest.packages.size());
        ASSERT_FALSE(honest.sender_item_labels.empty());

        vector<ResultPackage> script;
        script.reserve(honest.packages.size() * 2);
        for (const auto &rp : honest.packages) {
            script.push_back(rp);
            script.push_back(rp);
        }

        ReplayChannel chl(std::move(script));
        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(
            query_result =
                receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl));

        // Labels must survive intact, not just the match flags.
        VerifyResults(honest, query_result);
    }

    TEST(HostileSenderTests, MultipleBinBundlesPerBundleIdxSurviveDeduplication)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);

        // Large enough that some bundle index overflows a single bin bundle. Sender::RunQuery
        // announces get_bin_bundle_count() packages and sends one per bin bundle, so several
        // packages then carry the same bundle_idx -- legitimately, with disjoint matches.
        //
        // This is why a receiver cannot defend itself by rejecting a repeated bundle_idx: doing
        // so silently discards real results for exactly the large databases this library exists
        // to serve. Duplicates have to be resolved where they actually collide, in the merge.
        HonestQuery honest = RunHonestQuery(receiver, params, 10000, 40, 20);
        ASSERT_LT(size_t(params.bundle_idx_count()), honest.packages.size());

        // Replay on top of that, so the same test covers both properties at once: every honest
        // package must still be merged, and the duplicates must still be dropped.
        vector<ResultPackage> script;
        script.reserve(honest.packages.size() * 2);
        for (const auto &rp : honest.packages) {
            script.push_back(rp);
            script.push_back(rp);
        }

        ReplayChannel chl(std::move(script));
        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(
            query_result =
                receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl));

        VerifyResults(honest, query_result);
    }

    TEST(HostileSenderTests, OutOfRangeBundleIdxIsIgnored)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // A package claiming a bundle_idx far outside the parameter set. This is a behaviour
        // contract rather than a crash guard: the index arithmetic runs in size_t with
        // mul_safe so it cannot wrap, and an unknown table index misses the translation table
        // anyway, so such a package is harmless on its own. The receiver rejects it up front
        // to avoid the wasted decryption, and either way the requirement is the same -- a
        // garbage bundle_idx is ignored, never fatal, and the rest of the answer still lands.
        vector<ResultPackage> script = honest.packages;
        ResultPackage out_of_range = honest.packages.front();
        out_of_range.bundle_idx = numeric_limits<uint32_t>::max();
        script.push_back(std::move(out_of_range));

        ReplayChannel chl(std::move(script));
        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(
            query_result =
                receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl));

        VerifyResults(honest, query_result);
    }

    TEST(HostileSenderTests, ProcessResultIgnoresDuplicatePackages)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // The same attack against the single-threaded public API, which callers use when they
        // drive the channel themselves. Nothing races on this path, so what matters here is
        // that a repeated match resolves to a single match instead of failing the query.
        vector<ResultPart> rps;
        rps.reserve(honest.packages.size() * 2);
        for (const auto &rp : honest.packages) {
            rps.push_back(make_unique<ResultPackage>(rp));
            rps.push_back(make_unique<ResultPackage>(rp));
        }

        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(query_result = receiver.process_result(honest.label_keys, honest.itt, rps));

        VerifyResults(honest, query_result);
    }

    TEST(HostileSenderTests, ProcessResultIgnoresNullPackages)
    {
        // As with OutOfRangeBundleIdxIsIgnored, a behaviour contract rather than a crash
        // guard. A null part is caught in more than one place -- process_result_part reports
        // an empty vector for it, and process_result skips any part whose size does not match
        // -- so it is never dereferenced. This test keeps that agreement from drifting.
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // A caller driving the channel by hand can easily end up with a null part, because
        // Channel::receive_result returns nullptr when nothing is available yet.
        vector<ResultPart> rps;
        rps.reserve(honest.packages.size() + 1);
        rps.push_back(nullptr);
        for (const auto &rp : honest.packages) {
            rps.push_back(make_unique<ResultPackage>(rp));
        }

        vector<MatchRecord> query_result;
        ASSERT_NO_THROW(query_result = receiver.process_result(honest.label_keys, honest.itt, rps));

        VerifyResults(honest, query_result);
    }
} // namespace APSITests
