// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <chrono>
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

        The script must hold exactly as many packages as the announced package_count. A
        worker that gets nothing back, from a channel reporting no failure, concludes the
        package is merely late and waits for it.
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

        /**
        Models a sender whose messages the channel consumes but cannot use. Every receive comes
        back empty and reports a failure, which is what a real channel does with a truncated,
        corrupt, or mistyped message: the bytes are off the wire and gone, and the message the
        caller is waiting for will never arrive.

        The receiver waits for a message by looping until it gets one, so this is precisely the
        input that decides whether the loop can end. A channel that reported nothing would leave
        the receiver waiting on data that no longer exists.
        */
        class UnreadablePeerChannel final : public NetworkChannel {
        public:
            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                set_receive_failed();
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                set_receive_failed();
                return nullptr;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                set_receive_failed();
                return nullptr;
            }
        }; // class UnreadablePeerChannel

        /**
        Answers every request with a well-formed response of a type the caller did not ask for,
        and applies the same type check the shipped channels apply.

        The check is what gives the fake its teeth. A caller that names the type it expects is
        told at once that the sender answered with something else. A caller that leaves the type
        open is handed the response, finds it unusable, drops it, and goes back to waiting for a
        message the sender considers already sent.
        */
        class WrongTypeResponseChannel final : public NetworkChannel {
        public:
            explicit WrongTypeResponseChannel(SenderOperationType response_type)
                : response_type_(response_type)
            {}

            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected) override
            {
                if (expected != SenderOperationType::sop_unknown && expected != response_type_) {
                    set_receive_failed();
                    return nullptr;
                }
                return make_response();
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                return nullptr;
            }

        private:
            unique_ptr<SenderOperationResponse> make_response() const
            {
                if (response_type_ == SenderOperationType::sop_oprf) {
                    return make_unique<SenderOperationResponseOPRF>();
                }

                auto response = make_unique<SenderOperationResponseParms>();
                response->params = make_unique<PSIParams>(create_params1());
                return response;
            }

            SenderOperationType response_type_;
        }; // class WrongTypeResponseChannel

        /**
        Answers an OPRF request with a well-formed response carrying the wrong number of hashes.

        Nothing about this message is malformed, so the channel has no reason to record a
        failure: it is a valid OPRF response that simply does not answer the question asked. The
        receiver has to notice on its own, because an empty hash list is indistinguishable from a
        genuine empty intersection everywhere downstream, and the CLI goes on to index a result
        vector by the caller's item count.
        */
        class MissizedOPRFResponseChannel final : public NetworkChannel {
        public:
            explicit MissizedOPRFResponseChannel(size_t item_count) : item_count_(item_count)
            {}

            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                auto response = make_unique<SenderOperationResponseOPRF>();
                response->data.resize(item_count_ * oprf_response_size);
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                return nullptr;
            }

        private:
            size_t item_count_;
        }; // class MissizedOPRFResponseChannel

        /**
        Answers a query by announcing more result packages than it goes on to deliver, then
        reporting a failure in place of the packages it withheld.

        This is the shape of the problem the announced count creates. Each worker claims a slot
        from that count before it reads anything, so once a package is consumed and lost there
        is a claimed slot no package will ever fill. The worker holding it has to learn that
        from the channel; a count alone cannot tell it, and neither can a null return.
        */
        class TruncatedReplayChannel final : public NetworkChannel {
        public:
            TruncatedReplayChannel(vector<ResultPackage> script, uint32_t announced_count)
                : script_(std::move(script)), announced_count_(announced_count)
            {}

            void send(unique_ptr<SenderOperation>) override
            {}

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
                response->package_count = announced_count_;
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                lock_guard<mutex> lock(mtx_);
                if (next_ >= script_.size()) {
                    set_receive_failed();
                    return nullptr;
                }
                return make_unique<ResultPackage>(script_[next_++]);
            }

        private:
            mutex mtx_;

            vector<ResultPackage> script_;

            uint32_t announced_count_;

            size_t next_ = 0;
        }; // class TruncatedReplayChannel

        /**
        Accepts everything and answers nothing, modelling a sender that takes a request and then
        goes quiet: connected, never closing, never replying.

        This is the case a failure flag cannot reach. Nothing has gone wrong on the wire, so
        there is nothing for the channel to report; the message the receiver wants is simply not
        coming. Only a clock can tell the receiver that. Construct with an announced package
        count to fall silent after the query response instead of before it.
        */
        class SilentChannel final : public NetworkChannel {
        public:
            SilentChannel() = default;

            explicit SilentChannel(uint32_t announced_count)
                : announced_count_(announced_count), answer_query_(true)
            {}

            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                if (!answer_query_) {
                    return nullptr;
                }

                auto response = make_unique<SenderOperationResponseQuery>();
                response->package_count = announced_count_;
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                return nullptr;
            }

        private:
            uint32_t announced_count_ = 0;

            bool answer_query_ = false;
        }; // class SilentChannel

        /**
        Answers a parameter request, but only after a delay, modelling a sender that is slow
        rather than hostile.

        A deadline that cannot tell these two apart is worse than no deadline, so this is the
        channel that pins down the difference.
        */
        class SlowParamsChannel final : public NetworkChannel {
        public:
            SlowParamsChannel(const PSIParams &params, chrono::milliseconds delay)
                : params_(params), answer_at_(chrono::steady_clock::now() + delay)
            {}

            void send(unique_ptr<SenderOperation>) override
            {}

            unique_ptr<SenderOperation> receive_operation(
                shared_ptr<SEALContext>, SenderOperationType) override
            {
                return nullptr;
            }

            void send(unique_ptr<SenderOperationResponse>) override
            {}

            unique_ptr<SenderOperationResponse> receive_response(SenderOperationType) override
            {
                if (chrono::steady_clock::now() < answer_at_) {
                    return nullptr;
                }

                auto response = make_unique<SenderOperationResponseParms>();
                response->params = make_unique<PSIParams>(params_);
                return response;
            }

            void send(unique_ptr<ResultPackage>) override
            {}

            unique_ptr<ResultPackage> receive_result(shared_ptr<SEALContext>) override
            {
                return nullptr;
            }

        private:
            PSIParams params_;

            chrono::steady_clock::time_point answer_at_;
        }; // class SlowParamsChannel

        /**
        Delivers a script of result packages one at a time with a gap between them, so that the
        whole exchange takes far longer than any single wait within it.

        The workers share one deadline, and this is what makes that necessary rather than
        merely tidy: while one worker is being served, the others are waiting on packages that
        have not been computed yet. If each worker measured only its own wait, the ones served
        last would time out on a sender that never stopped making progress.
        */
        class DripChannel final : public NetworkChannel {
        public:
            DripChannel(vector<ResultPackage> script, chrono::milliseconds gap)
                : script_(std::move(script)), gap_(gap)
            {}

            uint32_t announced_count() const
            {
                return static_cast<uint32_t>(script_.size());
            }

            void send(unique_ptr<SenderOperation>) override
            {}

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
                response->package_count = announced_count();
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

                if (chrono::steady_clock::now() < next_due_) {
                    return nullptr;
                }

                next_due_ = chrono::steady_clock::now() + gap_;
                return make_unique<ResultPackage>(script_[next_++]);
            }

        private:
            mutex mtx_;

            vector<ResultPackage> script_;

            chrono::milliseconds gap_;

            chrono::steady_clock::time_point next_due_ = chrono::steady_clock::now();

            size_t next_ = 0;
        }; // class DripChannel

        /**
        Runs an exchange that is expected to end because the channel reported a failure it cannot
        recover from, and checks that this is in fact why it ended.

        Looking at the message is what keeps the test honest. Every wait has two ways out, the
        reported failure and the deadline, and both raise the same exception type. A test that
        checks only the type is satisfied by either, so it would go on passing if the failure
        went unnoticed and the deadline cleaned up minutes later. The generous timeout and the
        tight bound on elapsed time say the same thing a second way: reaching the deadline at all
        is a failure of this test.
        */
        template <typename Callable>
        void ExpectFailureIsReported(const Channel &chl, Callable exchange)
        {
            auto start = chrono::steady_clock::now();
            try {
                exchange();
                FAIL() << "the exchange was expected to throw";
            } catch (const runtime_error &ex) {
                ASSERT_NE(string::npos, string(ex.what()).find("failed to receive"));
            }

            ASSERT_LT(chrono::steady_clock::now() - start, 5s);
            ASSERT_TRUE(chl.receive_failed());
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

    // The tests below cover what happens when the sender's messages cannot be used at all,
    // rather than being valid messages used maliciously. Every receiver wait is a loop over a
    // null return, so an unusable message has to end the wait. Left unreported it would end
    // nothing: the receiver would keep asking for a message the sender has already sent, spent,
    // and will not send again, for as long as the process lives.
    //
    // A regression in any of these shows up as a failure rather than as a hang: each test caps
    // its own wait and asserts both that the call gives up and that it does so promptly.

    TEST(HostileSenderTests, ParameterRequestEndsWhenTheResponseCannotBeRead)
    {
        SetUpTestLoggingAndThreads();

        UnreadablePeerChannel chl;
        ExpectFailureIsReported(chl, [&] { (void)Receiver::RequestParams(chl, 30s); });
    }

    TEST(HostileSenderTests, OPRFRequestEndsWhenTheResponseCannotBeRead)
    {
        SetUpTestLoggingAndThreads();

        vector<Item> items;
        items.emplace_back(1, 1);

        UnreadablePeerChannel chl;
        ExpectFailureIsReported(chl, [&] { (void)Receiver::RequestOPRF(items, chl, 30s); });
    }

    TEST(HostileSenderTests, OPRFRequestRejectsAResponseWithTheWrongNumberOfHashes)
    {
        SetUpTestLoggingAndThreads();

        vector<Item> items;
        items.emplace_back(1, 1);
        items.emplace_back(2, 2);
        items.emplace_back(3, 3);

        // One hash where three were asked for. Returning what arrived would hand the caller an
        // empty result that reads as an empty intersection.
        MissizedOPRFResponseChannel chl(1);
        ASSERT_THROW((void)Receiver::RequestOPRF(items, chl, 30s), runtime_error);

        // An empty response is refused on the same grounds, and matters most: it is the reply
        // that would otherwise read as an empty intersection.
        MissizedOPRFResponseChannel ragged(0);
        ASSERT_THROW((void)Receiver::RequestOPRF(items, ragged, 30s), runtime_error);
    }

    TEST(HostileSenderTests, QueryEndsWhenTheResponseCannotBeRead)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        UnreadablePeerChannel chl;
        ExpectFailureIsReported(chl, [&] {
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl, 30s);
        });
    }

    // A response of the wrong type is a message the receiver can read and cannot use. The
    // channel is the only party positioned to notice, and it can only notice if the caller
    // tells it what it is waiting for. The tests below pin that argument down at each of the
    // three call sites: drop it and the mismatched response is discarded in silence, leaving
    // the receiver waiting on a message the sender has already sent.

    TEST(HostileSenderTests, ParameterRequestRejectsAResponseOfTheWrongType)
    {
        SetUpTestLoggingAndThreads();

        WrongTypeResponseChannel chl(SenderOperationType::sop_oprf);
        ExpectFailureIsReported(chl, [&] { (void)Receiver::RequestParams(chl, 30s); });
    }

    TEST(HostileSenderTests, OPRFRequestRejectsAResponseOfTheWrongType)
    {
        SetUpTestLoggingAndThreads();

        vector<Item> items;
        items.emplace_back(1, 1);

        WrongTypeResponseChannel chl(SenderOperationType::sop_parms);
        ExpectFailureIsReported(chl, [&] { (void)Receiver::RequestOPRF(items, chl, 30s); });
    }

    TEST(HostileSenderTests, QueryRejectsAResponseOfTheWrongType)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        WrongTypeResponseChannel chl(SenderOperationType::sop_parms);
        ExpectFailureIsReported(chl, [&] {
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl, 30s);
        });
    }

    TEST(HostileSenderTests, QueryEndsWhenAnnouncedResultPackagesGoMissing)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        ASSERT_LE(size_t(2), honest.packages.size());

        // Deliver every package but the last, while announcing them all. The workers between
        // them claim every announced slot, so one of them ends up waiting on the package that
        // was never delivered. That worker cannot distinguish a withheld package from a late
        // one on its own, and the count it already decremented cannot tell it either.
        vector<ResultPackage> script(honest.packages.begin(), honest.packages.end() - 1);
        auto announced = static_cast<uint32_t>(honest.packages.size());

        TruncatedReplayChannel chl(std::move(script), announced);

        auto start = chrono::steady_clock::now();
        ASSERT_THROW(
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl),
            runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        // Every worker has to come back, not just the one that saw the failure, or the join
        // that waits for them never returns. The bound is loose on purpose: it is here to
        // catch a wait that resolves only after some long timeout, not to measure anything.
        ASSERT_LT(elapsed, chrono::seconds(60));
    }

    TEST(HostileSenderTests, QueryEndsWhenNoResultPackagesArriveAtAll)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // Announcing packages and then delivering none is the cheapest version of the same
        // attack: one small, well-formed response commits the receiver to waiting for work that
        // never comes.
        TruncatedReplayChannel chl({}, static_cast<uint32_t>(honest.packages.size()));

        auto start = chrono::steady_clock::now();
        ASSERT_THROW(
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl),
            runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        ASSERT_LT(elapsed, chrono::seconds(60));
    }

    // A sender that goes silent is the one shape of misbehaviour a failure flag cannot catch.
    // Nothing has gone wrong on the wire for the channel to report, so the receiver's only
    // evidence that the exchange is dead is that time has passed without a word.
    //
    // These tests use short explicit timeouts. The default is deliberately generous, and a test
    // that waited it out would be indistinguishable from the hang it exists to rule out.

    TEST(HostileSenderTests, ParameterRequestGivesUpOnASilentSender)
    {
        SetUpTestLoggingAndThreads();

        SilentChannel chl;

        auto start = chrono::steady_clock::now();
        ASSERT_THROW((void)Receiver::RequestParams(chl, 200ms), runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        // Giving up early would mean the deadline is not the thing that ended the wait.
        ASSERT_GE(elapsed, 200ms);
        ASSERT_LT(elapsed, chrono::seconds(30));
    }

    TEST(HostileSenderTests, OPRFRequestGivesUpOnASilentSender)
    {
        SetUpTestLoggingAndThreads();

        vector<Item> items;
        items.emplace_back(1, 1);

        SilentChannel chl;

        auto start = chrono::steady_clock::now();
        ASSERT_THROW((void)Receiver::RequestOPRF(items, chl, 200ms), runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        ASSERT_GE(elapsed, 200ms);
        ASSERT_LT(elapsed, chrono::seconds(30));
    }

    TEST(HostileSenderTests, QueryGivesUpOnASilentSender)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        SilentChannel chl;

        auto start = chrono::steady_clock::now();
        ASSERT_THROW(
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl, 200ms),
            runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        ASSERT_GE(elapsed, 200ms);
        ASSERT_LT(elapsed, chrono::seconds(30));
    }

    TEST(HostileSenderTests, QueryGivesUpWhenResultPackagesStopArriving)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        HonestQuery honest = RunHonestQuery(receiver, params, 1000, 20, 10);

        // One small, well-formed query response commits every worker to waiting, and then
        // nothing else is ever sent. This is the cheapest denial of service the protocol
        // permits, and the flag cannot see it: no message was mangled, none was sent at all.
        SilentChannel chl(static_cast<uint32_t>(honest.packages.size()));

        auto start = chrono::steady_clock::now();
        ASSERT_THROW(
            (void)receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl, 200ms),
            runtime_error);
        auto elapsed = chrono::steady_clock::now() - start;

        ASSERT_GE(elapsed, 200ms);
        ASSERT_LT(elapsed, chrono::seconds(30));
    }

    TEST(HostileSenderTests, ParameterRequestWaitsOutASenderThatIsMerelySlow)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        SlowParamsChannel chl(params, 300ms);

        // The answer arrives well after the receiver starts waiting, but well inside the
        // deadline, and a deadline that cannot tell slow from silent is useless.
        PSIParams received = Receiver::RequestParams(chl, chrono::seconds(30));
        ASSERT_EQ(params.to_string(), received.to_string());
    }

    TEST(HostileSenderTests, AZeroTimeoutWaitsIndefinitely)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        SlowParamsChannel chl(params, 300ms);

        // Zero is documented as "no deadline". Read as a deadline of zero it would expire on the
        // first check, turning the opt-out into the strictest possible setting.
        PSIParams received = Receiver::RequestParams(chl, chrono::milliseconds::zero());
        ASSERT_EQ(params.to_string(), received.to_string());
    }

    TEST(HostileSenderTests, ANegativeTimeoutIsAlreadyExpired)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        // A caller passing on what remains of a wider budget writes deadline minus now, which
        // goes negative the moment the budget is spent. Read as "no deadline" that would mean
        // the more careful caller is the one who gets no protection, and it would fail open
        // silently. It counts as a deadline already passed instead.
        SlowParamsChannel chl(params, 300ms);
        ASSERT_THROW(Receiver::RequestParams(chl, -1ms), runtime_error);
    }

    TEST(HostileSenderTests, QueryOutlivesItsDeadlineWhileThePackagesKeepComing)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        Receiver receiver(params);
        // A larger sender set is what makes the point: it yields enough bin bundles that the
        // packages, spaced out, outlast the deadline several times over.
        HonestQuery honest = RunHonestQuery(receiver, params, 40000, 40, 20);

        auto package_count = static_cast<int>(honest.packages.size());
        ASSERT_LE(12, package_count);

        // Spaced so that the exchange as a whole takes longer than the deadline while no single
        // wait comes close to it. The deadline bounds silence, not the length of the query, and
        // a query is entitled to run for as long as the sender keeps producing.
        //
        // The deadline is derived from the number of packages rather than fixed, so that the
        // two margins hold whatever the sender's data packs into. Three quarters of the drip
        // leaves the exchange comfortably longer than the deadline, while still leaving each
        // individual wait, a gap plus the worker's poll interval, several times inside it. A
        // machine slow enough to stretch one delivery past the deadline is the only way this
        // fails, and that takes an order of magnitude.
        auto gap = 150ms;
        auto timeout = (gap * (package_count - 1) * 3) / 4;
        ASSERT_GT(gap * (package_count - 1), timeout);
        ASSERT_GT(timeout, 5 * gap);

        DripChannel chl(honest.packages, gap);

        auto start = chrono::steady_clock::now();
        auto query_result =
            receiver.request_query(honest.hashed_recv_items, honest.label_keys, chl, timeout);
        auto elapsed = chrono::steady_clock::now() - start;

        ASSERT_GT(elapsed, timeout);
        VerifyResults(honest, query_result);
    }
} // namespace APSITests
