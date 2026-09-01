// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
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
        /**
        Stops a dispatcher running on another thread and waits for it, on every exit path.

        A test body leaves through a fatal assertion or a thrown exception as readily as it leaves
        through its last statement, and a dispatcher loops until it is told to stop. Stopping it
        from the end of the body therefore only covers the case where nothing went wrong: any
        other exit leaves the loop running and blocks the destructor of the future that holds it,
        so the binary stops producing output instead of reporting which assertion failed. The
        tests these guard are the ones that pin down the receiver's willingness to give up, and a
        regression in those has to be visible.
        */
        class DispatcherStopper {
        public:
            DispatcherStopper(atomic<bool> &stop, future<void> &running)
                : stop_(stop), running_(running)
            {}

            DispatcherStopper(const DispatcherStopper &) = delete;

            DispatcherStopper &operator=(const DispatcherStopper &) = delete;

            ~DispatcherStopper()
            {
                stop_ = true;
                if (running_.valid()) {
                    try {
                        running_.get();
                    } catch (const exception &) {
                        // The dispatcher's own failure must not replace the assertion that is
                        // already on its way out, and must not leave the process by way of a
                        // destructor.
                    }
                }
            }

        private:
            atomic<bool> &stop_;

            future<void> &running_;
        }; // class DispatcherStopper

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

                case SenderOperationType::sop_query: {
                    auto response = make_unique<SenderOperationResponseQuery>();
                    response->package_count = announced_package_count;
                    SendResponseTo(chl, client_id, std::move(response));
                    break;
                }

                default:
                    break;
                }
            }
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

        future<void> sender_f = async(launch::async, [&]() {
            try {
                ZMQSenderDispatcher dispatcher(sender_db);
                dispatcher.run(
                    stop_sender, 0, [&listening_on](int port) { listening_on.set_value(port); });
            } catch (...) {
                try {
                    listening_on.set_exception(current_exception());
                } catch (const future_error &) {
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

        vector<HashedItem> hashed_recv_items;
        LabelKeyVector label_keys;
        tie(hashed_recv_items, label_keys) = Receiver::RequestOPRF(recv_items, recv_chl, 30s);

        auto query_result = receiver.request_query(hashed_recv_items, label_keys, recv_chl, 30s);

        ASSERT_EQ(size_t(3), query_result.size());
        ASSERT_TRUE(query_result[0].found);
        ASSERT_TRUE(query_result[1].found);
        ASSERT_FALSE(query_result[2].found);
    }

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
            async(launch::async, [&]() { RunSilentSender(sender_db, 2, stop_sender, silent_chl); });
        DispatcherStopper stopper(stop_sender, sender_f);

        ZMQReceiverChannel recv_chl;
        recv_chl.connect(address);

        Receiver receiver(params);

        vector<Item> recv_items = { sender_items[0], sender_items[1] };

        vector<HashedItem> hashed_recv_items;
        LabelKeyVector label_keys;
        tie(hashed_recv_items, label_keys) = Receiver::RequestOPRF(recv_items, recv_chl, 30s);

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
} // namespace APSITests
