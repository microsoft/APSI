// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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

// ZeroMQ
#include "zmq.hpp"
#include "zmq_addon.hpp"

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
        void SetUpTestLoggingAndThreads()
        {
            SetLogger(Logger::Create({}, {}, {}));
            SetLogLevel(LogLevel::info);

            size_t num_threads = thread::hardware_concurrency();
            ThreadPoolMgr::SetThreadCount(num_threads);
            ThreadPoolMgr::SetPoolWorkerCount(num_threads * 2);
        }

        /**
        A port with nothing behind it.

        Taken by binding a socket and then dropping it, so the number is one the operating system
        was willing to hand out and is free again by the time it is returned. Another process
        could in principle claim it in between; that would not weaken the test, because a peer
        that does not speak the protocol leaves the receiver waiting exactly as an absent one
        does.
        */
        int unused_port()
        {
            ZMQSenderChannel probe;
            probe.bind(any_port_bind_address());
            int port = bound_port(probe);
            probe.disconnect();

            return port;
        }

        shared_ptr<SenderDB> CreateSenderDB(const PSIParams &params, const vector<Item> &items)
        {
            auto sender_db = make_shared<SenderDB>(params, 0);
            sender_db->set_data(items);
            return sender_db;
        }

        /**
        Sends a raw multipart message straight at a bound sender, bypassing the channel that
        would otherwise shape it.

        Going under the channel is the only way to produce a request no honest receiver would
        ever send. The sender's socket is a router, so it prepends the sending peer's routing
        id: a message written here with n parts reaches the sender with n + 1.
        */
        void SendRawFrames(const string &address, const vector<string> &frames)
        {
            zmq::context_t context;
            zmq::socket_t socket(context, zmq::socket_type::dealer);

            // This helper exists to talk to a sender that may not be listening, so closing the
            // socket must never wait on what it could not deliver.
            socket.set(zmq::sockopt::linger, 0);
            socket.connect(address);

            zmq::multipart_t msg;
            for (const auto &frame : frames) {
                msg.addstr(frame);
            }
            msg.send(socket);

            // Let the sender pick the message up before the socket goes away under it.
            this_thread::sleep_for(200ms);
        }

        /**
        Forwards a response to the client the request came from, the way every dispatch path
        does.
        */
        void SendResponseTo(
            ZMQSenderChannel &chl,
            const vector<unsigned char> &client_id,
            unique_ptr<SenderOperationResponse> response)
        {
            auto network_response = make_unique<ZMQSenderOperationResponse>();
            network_response->sop_response = std::move(response);
            network_response->client_id = client_id;
            chl.send(std::move(network_response));
        }

        /**
        Answers a query from the given client on the given channel.
        */
        using QueryAnswerer = function<void(
            ZMQSenderChannel &, const vector<unsigned char> &, unique_ptr<SenderOperation>)>;

        /**
        Serves parameter and OPRF requests honestly, and leaves every query to answer_query.
        */
        void RunFakeSender(
            const shared_ptr<SenderDB> &sender_db,
            const QueryAnswerer &answer_query,
            atomic<bool> &stop,
            ZMQSenderChannel &chl)
        {
            OPRFKey oprf_key = sender_db->get_oprf_key();

            while (!stop) {
                auto sop = chl.receive_network_operation(sender_db->get_seal_context());
                if (!sop) {
                    this_thread::sleep_for(50ms);
                    continue;
                }

                vector<unsigned char> client_id = sop->client_id;

                switch (sop->sop->type()) {
                case SenderOperationType::sop_parms:
                    Sender::RunParams(
                        to_params_request(std::move(sop->sop)),
                        sender_db,
                        chl,
                        [&client_id](Channel &c, unique_ptr<SenderOperationResponse> response) {
                            SendResponseTo(
                                static_cast<ZMQSenderChannel &>(c), client_id, std::move(response));
                        });
                    break;

                case SenderOperationType::sop_oprf:
                    Sender::RunOPRF(
                        to_oprf_request(std::move(sop->sop)),
                        oprf_key,
                        chl,
                        [&client_id](Channel &c, unique_ptr<SenderOperationResponse> response) {
                            SendResponseTo(
                                static_cast<ZMQSenderChannel &>(c), client_id, std::move(response));
                        });
                    break;

                case SenderOperationType::sop_query:
                    answer_query(chl, client_id, std::move(sop->sop));
                    break;

                default:
                    break;
                }
            }
        }

        /**
        Serves parameter and OPRF requests honestly, then answers a query by announcing result
        packages it never sends.

        The announcement is what commits the receiver: each of its result workers claims one of
        the announced packages and then waits for it. Reaching that state over a real socket is
        the point of the fake, because it is where a blocking receive would otherwise park a
        worker in the kernel, holding the channel's receive mutex, with its siblings and the
        join that waits for them stuck behind it.
        */
        void RunSilentSender(
            const shared_ptr<SenderDB> &sender_db,
            uint32_t announced_package_count,
            atomic<bool> &stop,
            ZMQSenderChannel &chl)
        {
            RunFakeSender(
                sender_db,
                [announced_package_count](
                    ZMQSenderChannel &c,
                    const vector<unsigned char> &client_id,
                    unique_ptr<SenderOperation>) {
                    auto response = make_unique<SenderOperationResponseQuery>();
                    response->package_count = announced_package_count;
                    SendResponseTo(c, client_id, std::move(response));
                },
                stop,
                chl);
        }
    } // namespace

    // A sender listens to anyone. One peer sending nonsense must cost that peer its own
    // exchange and nothing more, so the tests below put a malformed request and a healthy one
    // through the same dispatcher and require the healthy one to be served in full.

    TEST(HostileZMQTests, DispatcherSurvivesMalformedRequests)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();

        vector<Item> sender_items;
        sender_items.reserve(100);
        for (size_t i = 0; i < 100; i++) {
            sender_items.emplace_back(i + 1, i + 1);
        }

        atomic<bool> stop_sender{ false };
        auto sender_db = CreateSenderDB(params, sender_items);

        // The dispatcher takes whichever port the operating system gives it, so the address is
        // settled only once it has bound. A dispatcher that fails before that reports the failure
        // here, rather than leaving the test waiting for a port that will never be announced.
        promise<int> listening_on;
        future<int> listening_on_f = listening_on.get_future();

        future<void> sender_f = async(launch::async, [&] {
            try {
                ZMQSenderDispatcher dispatcher(sender_db);
                dispatcher.run(
                    stop_sender, 0, [&listening_on](int port) { listening_on.set_value(port); });
            } catch (...) {
                try {
                    listening_on.set_exception(current_exception());
                } catch (const future_error &) { // NOLINT(bugprone-empty-catch): see below
                    // The port was already announced, so the bind succeeded and the failure came
                    // later. Nothing is waiting on the promise any more.
                }
                throw;
            }
        });
        DispatcherStopper stopper(stop_sender, sender_f);

        string address = connect_address(listening_on_f.get());

        // Too few parts, too many parts, and the right number carrying nothing the sender can
        // read. Each one leaves the sender's channel marked as failed, and that mark is sticky,
        // so a sender that consulted it would refuse every client from here on.
        SendRawFrames(address, { "one part" });
        SendRawFrames(address, { "far", "too", "many", "parts" });
        SendRawFrames(address, { "not a header", "not an operation" });

        ZMQReceiverChannel recv_chl;
        recv_chl.connect(address);

        PSIParams received_params = Receiver::RequestParams(recv_chl, 30s);
        ASSERT_EQ(params.to_string(), received_params.to_string());

        Receiver receiver(params);

        vector<Item> recv_items = { sender_items[0], sender_items[1] };

        // A third item the sender does not have, so the answer has to distinguish rather than
        // just report everything as found.
        constexpr uint64_t absent_item_word = numeric_limits<uint64_t>::max();
        recv_items.emplace_back(absent_item_word, absent_item_word);

        auto [hashed_recv_items, label_keys] = Receiver::RequestOPRF(recv_items, recv_chl, 30s);

        auto query_result = receiver.request_query(hashed_recv_items, label_keys, recv_chl, 30s);

        ASSERT_EQ(size_t(3), query_result.size());
        ASSERT_TRUE(query_result[0].found);
        ASSERT_TRUE(query_result[1].found);
        ASSERT_FALSE(query_result[2].found);
    }

    namespace {
        /**
        Collects the errors logged while it exists, from any thread, and silences logging again
        when it is destroyed.
        */
        class ErrorLog {
        public:
            ErrorLog()
            {
                array<Logger::log_handler_t, Logger::level_count> log_handlers{};
                log_handlers[static_cast<size_t>(LogLevel::error)] = [this](const string &msg) {
                    lock_guard<mutex> lock(mtx_);
                    errors_.push_back(msg);
                };
                SetLogger(Logger::Create(std::move(log_handlers), {}, {}));
            }

            ~ErrorLog()
            {
                // Replacing the logger closes this one, which waits for a handler that is still
                // running, so nothing refers to this object once it is gone.
                SetLogger(Logger::Create({}, {}, {}));
            }

            ErrorLog(const ErrorLog &) = delete;

            ErrorLog &operator=(const ErrorLog &) = delete;

            /**
            Waits until an error containing the given text has been logged, and returns false if
            none has been within the given time.
            */
            bool wait_for(const string &text, chrono::milliseconds timeout) const
            {
                auto deadline = chrono::steady_clock::now() + timeout;
                while (chrono::steady_clock::now() < deadline) {
                    {
                        lock_guard<mutex> lock(mtx_);
                        for (const auto &error : errors_) {
                            if (error.find(text) != string::npos) {
                                return true;
                            }
                        }
                    }
                    this_thread::sleep_for(50ms);
                }
                return false;
            }

        private:
            mutable mutex mtx_;

            vector<string> errors_;
        };
    } // namespace

    // The deadline is checked between receive calls, so it protects a receiver only as far as
    // the channel hands control back. Every other test of it runs against a fake that returns
    // immediately; this one runs against a real socket, where a blocking receive is what the
    // channel actually does and a receive timeout is the only reason it ever returns.

    TEST(HostileZMQTests, QueryGivesUpOnASilentSenderOverZMQ)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();

        vector<Item> sender_items;
        sender_items.reserve(100);
        for (size_t i = 0; i < 100; i++) {
            sender_items.emplace_back(i + 1, i + 1);
        }

        atomic<bool> stop_sender{ false };
        auto sender_db = CreateSenderDB(params, sender_items);

        // Bound here rather than inside the sender thread, so that the address is known before
        // the thread starts and a bind that fails surfaces as a failure of this test rather than
        // as a wait that never ends. Only the sender thread uses the channel once it is running.
        ZMQSenderChannel silent_chl;
        silent_chl.bind(any_port_bind_address());
        string address = connect_address(silent_chl);

        future<void> sender_f =
            async(launch::async, [&] { RunSilentSender(sender_db, 2, stop_sender, silent_chl); });
        DispatcherStopper stopper(stop_sender, sender_f);

        ZMQReceiverChannel recv_chl;
        recv_chl.connect(address);

        Receiver receiver(params);

        vector<Item> recv_items = { sender_items[0], sender_items[1] };

        auto [hashed_recv_items, label_keys] = Receiver::RequestOPRF(recv_items, recv_chl, 30s);

        // Comfortably longer than the channel's receive poll interval, so the workers have to
        // come back from a blocking receive several times before the deadline is reached.
        auto timeout = 3s;

        auto start = chrono::steady_clock::now();
        try {
            (void)receiver.request_query(hashed_recv_items, label_keys, recv_chl, timeout);
            FAIL() << "the query was expected to give up on a sender that sends nothing";
        } catch (const runtime_error &ex) {
            ASSERT_NE(string::npos, string(ex.what()).find("timed out"));
        }
        auto elapsed = chrono::steady_clock::now() - start;

        // Waiting out the deadline is required; a query that ends sooner ended for some other
        // reason. The upper bound is the unwinding cost, one poll interval per worker queued
        // behind the receive mutex, and is generous against it.
        ASSERT_GE(elapsed, timeout);
        ASSERT_LT(elapsed, 60s);
    }

    // Escaping the wait is only half of not hanging. A receiver that gives up still has to be
    // able to put the channel down, and its request is still sitting in the outbound queue with
    // no peer to collect it.

    TEST(HostileZMQTests, ChannelCanBePutDownAfterGivingUpOnAPeer)
    {
        SetUpTestLoggingAndThreads();

        auto start = chrono::steady_clock::now();
        {
            ZMQReceiverChannel chl;

            // Nothing is listening here and nothing ever will be, so the request can never be
            // delivered.
            chl.connect(connect_address(unused_port()));

            try {
                (void)Receiver::RequestParams(chl, 2s);
                FAIL() << "the request was expected to give up on a peer that is not there";
            } catch (const runtime_error &ex) {
                ASSERT_NE(string::npos, string(ex.what()).find("timed out"));
            }
        }
        auto elapsed = chrono::steady_clock::now() - start;

        // Reaching this line at all is most of the assertion: an unbounded wait on the queued
        // request would never return. The bound catches it turning into something merely slow.
        ASSERT_LT(elapsed, 60s);
    }

    namespace {
        /**
        Answers a query as an honest sender does, and then sends one result package more: a copy
        of the first, as misreport leaves it. The response announces it, so that the receiver
        waits for every package, the honest ones and the copy.
        */
        void AnswerWithOneMorePackage(
            const shared_ptr<SenderDB> &sender_db,
            const function<void(ResultPackage &)> &misreport,
            ZMQSenderChannel &chl,
            const vector<unsigned char> &client_id,
            unique_ptr<SenderOperation> sop)
        {
            // Sender::RunQuery hands over the packages from several tasks at once, so they are
            // collected under a lock and sent once all of them are there
            mutex packages_mtx;
            vector<unique_ptr<ResultPackage>> packages;
            Query query(to_query_request(std::move(sop)), sender_db);
            Sender::RunQuery(
                query,
                chl,
                [](Channel &, Response) {},
                [&](Channel &, ResultPart rp) {
                    lock_guard<mutex> lock(packages_mtx);
                    packages.push_back(std::move(rp));
                });

            auto copy = make_unique<ResultPackage>(*packages.front());
            misreport(*copy);
            packages.push_back(std::move(copy));

            auto response = make_unique<SenderOperationResponseQuery>();
            response->package_count = static_cast<uint32_t>(packages.size());
            SendResponseTo(chl, client_id, std::move(response));

            for (auto &rp : packages) {
                auto network_rp = make_unique<ZMQResultPackage>();
                network_rp->rp = std::move(rp);
                network_rp->client_id = client_id;
                chl.send(std::move(network_rp));
            }
        }

        /**
        Queries, over a real socket, a sender that answers with one result package more than an
        honest sender, a copy of the first. As it is, the copy is ignored, so a first query gets
        the honest answer. As misreport changes it, the receiver's channel refuses it with the
        given error, and a second query fails, although every honest package arrives as well.
        */
        void ExpectMisreportedPackageFailsTheQuery(
            const shared_ptr<SenderDB> &sender_db,
            const function<void(ResultPackage &)> &misreport,
            const string &refusal)
        {
            ErrorLog errors;
            atomic<bool> stop_sender{ false };
            atomic<bool> misreporting{ false };

            ZMQSenderChannel sender_chl;
            sender_chl.bind(any_port_bind_address());
            string address = connect_address(sender_chl);

            future<void> sender_f = async(launch::async, [&] {
                RunFakeSender(
                    sender_db,
                    [&](ZMQSenderChannel &chl,
                        const vector<unsigned char> &client_id,
                        unique_ptr<SenderOperation> sop) {
                        AnswerWithOneMorePackage(
                            sender_db,
                            [&](ResultPackage &rp) {
                                if (misreporting) {
                                    misreport(rp);
                                }
                            },
                            chl,
                            client_id,
                            std::move(sop));
                    },
                    stop_sender,
                    sender_chl);
            });
            DispatcherStopper stopper(stop_sender, sender_f);

            ZMQReceiverChannel recv_chl;
            recv_chl.connect(address);

            // Two items the sender has, and one it does not
            vector<Item> recv_items = { Item(1, 1), Item(2, 2) };
            constexpr uint64_t absent_item_word = numeric_limits<uint64_t>::max();
            recv_items.emplace_back(absent_item_word, absent_item_word);

            Receiver receiver(sender_db->get_params());
            auto [hashed_recv_items, label_keys] = Receiver::RequestOPRF(recv_items, recv_chl, 30s);

            // The copy as it is, which is ignored
            vector<MatchRecord> query_result =
                receiver.request_query(hashed_recv_items, label_keys, recv_chl, 30s);
            ASSERT_EQ(size_t(3), query_result.size());
            for (size_t i = 0; i < 2; i++) {
                ASSERT_TRUE(query_result[i].found);
                if (sender_db->is_labeled()) {
                    ASSERT_EQ(sender_db->get_label(recv_items[i]), query_result[i].label.value());
                }
            }
            ASSERT_FALSE(query_result[2].found);
            ASSERT_FALSE(recv_chl.receive_failed());

            // The copy as misreport changes it, which is refused
            misreporting = true;
            try {
                (void)receiver.request_query(hashed_recv_items, label_keys, recv_chl, 30s);
                FAIL() << "the query was expected to fail on the misreported package";
            } catch (const runtime_error &ex) {
                ASSERT_STREQ("failed to receive the result package", ex.what());
            }
            ASSERT_TRUE(recv_chl.receive_failed());
            ASSERT_TRUE(errors.wait_for(refusal, 5s));
        }
    } // namespace

    // Without match tags, the shipped channels refuse a result package for a bundle index the
    // parameters do not have, or with more label parts than its label and nonce take, as
    // ResultPackage::load does with the parameters, and the failed receive fails the whole query.
    // A channel that inherits Channel::receive_result_for checks less; see
    // HostileSenderTests.OutOfRangeBundleIdxIsIgnored.

    TEST(HostileZMQTests, OutOfRangeBundleIdxFailsTheQueryOverZMQ)
    {
        SetUpTestLoggingAndThreads();

        PSIParams params = create_params1();
        ASSERT_FALSE(params.uses_tags());
        ASSERT_EQ(uint32_t(4), params.bundle_idx_count());

        vector<Item> sender_items;
        sender_items.reserve(100);
        for (size_t i = 0; i < 100; i++) {
            sender_items.emplace_back(i + 1, i + 1);
        }
        auto sender_db = CreateSenderDB(params, sender_items);

        // The first bundle index the parameters do not have
        ASSERT_NO_FATAL_FAILURE(ExpectMisreportedPackageFailsTheQuery(
            sender_db,
            [](ResultPackage &rp) { rp.bundle_idx = 4; },
            "failed to load ResultPackage: result package is for bundle index 4 but the "
            "parameters have only 4"));
    }

    TEST(HostileZMQTests, ExtraLabelPartFailsTheQueryOverZMQ)
    {
        SetUpTestLoggingAndThreads();

        // A 10-byte label and a 4-byte nonce take one label part of 128 bits
        PSIParams params = create_params1();
        ASSERT_FALSE(params.uses_tags());
        ASSERT_EQ(uint32_t(128), params.item_bit_count());

        vector<pair<Item, Label>> sender_items;
        sender_items.reserve(100);
        for (size_t i = 0; i < 100; i++) {
            sender_items.emplace_back(
                Item(i + 1, i + 1), create_label(static_cast<unsigned char>(i + 1), 10));
        }
        auto sender_db = make_shared<SenderDB>(params, 10, 4, true);
        sender_db->set_data(sender_items);

        ASSERT_NO_FATAL_FAILURE(ExpectMisreportedPackageFailsTheQuery(
            sender_db,
            [](ResultPackage &rp) {
                SEALObject<Ciphertext> extra_part = rp.label_result.back();
                rp.label_result.push_back(std::move(extra_part));
            },
            "failed to load ResultPackage: result package has 2 label parts but at most 1 are "
            "expected"));
    }
} // namespace APSITests
