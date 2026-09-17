// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <chrono>
#include <string>
#include <thread>
#include <utility>

// SEAL
#include "seal/keygenerator.h"
#include "seal/publickey.h"

// APSI
#include "apsi/network/zmq/zmq_channel.h"

// APSI test support
#include "support/zmq_test_utils.h"

// ZeroMQ
#include "zmq_addon.hpp"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace std::chrono_literals;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        // The shared server/client channels are bound/connected once and reused across every test
        // in the fixture. Function-local statics defer their (potentially throwing) construction to
        // first use, where the exception can propagate normally, rather than during dynamic
        // initialization.
        ZMQSenderChannel &server()
        {
            static ZMQSenderChannel instance;
            return instance;
        }

        ZMQReceiverChannel &client()
        {
            static ZMQReceiverChannel instance;
            return instance;
        }

        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 16;
                table_params.table_size = 512;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        shared_ptr<CryptoContext> get_context()
        {
            static shared_ptr<CryptoContext> context = nullptr;
            if (!context) {
                context = make_shared<CryptoContext>(*get_params());
                KeyGenerator keygen(*context->seal_context());
                context->set_secret(keygen.secret_key());
                RelinKeys rlk;
                keygen.create_relin_keys(rlk);
                context->set_evaluator(std::move(rlk));
            }

            return context;
        }
    } // namespace

    class ZMQChannelTests : public ::testing::Test {
    protected:
        ZMQChannelTests()
        {
            if (!server().is_connected()) {
                server().bind(any_port_bind_address());
            }

            if (!client().is_connected()) {
                client().connect(connect_address(server()));
            }

            // Set up the context ahead of time
            (void)get_context();
        }

        // No destructor: the fixture is constructed and destroyed for every test, but the shared
        // server()/client() channels are intentionally left connected so the port is bound only
        // once. The implicit destructor (public, virtual via the base) is exactly what we want.
    };

    TEST_F(ZMQChannelTests, ThrowWithoutConnectTest)
    {
        // ZMQSenderChannel and ZMQReceiverChannel are identical for the purposes of this test
        ZMQSenderChannel mychannel;

        // Receives
        ASSERT_THROW(mychannel.receive_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_network_operation(nullptr), runtime_error);
        ASSERT_THROW(mychannel.receive_response(), runtime_error);
        ASSERT_THROW(mychannel.receive_result(nullptr), runtime_error);

        // Sends
        ASSERT_THROW(mychannel.send(make_unique<ResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<ZMQResultPackage>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<SenderOperationResponseParms>()), runtime_error);
        ASSERT_THROW(mychannel.send(make_unique<ZMQSenderOperationResponse>()), runtime_error);
    }

    TEST_F(ZMQChannelTests, ChannelIsDestructibleAfterAFailedBindOrConnect)
    {
        // Terminating a ZeroMQ context blocks until every socket in it is closed, and the socket
        // is created before the bind or connect that may throw. A channel whose bind failed must
        // therefore still close its socket on the way out, even though it never became connected
        // and its cleanup path is keyed on exactly that.
        //
        // A regression here does not fail this test, it hangs the whole binary with no output, so
        // reaching the end of the test body is the assertion. Note also that the fix cannot be to
        // call disconnect() unconditionally from the destructor: disconnect() begins by throwing
        // when the channel is not connected, and a destructor has to swallow that, which leaves
        // the socket open and the hang in place.
        {
            ZMQSenderChannel occupied;
            occupied.bind(any_port_bind_address());
            string taken = "tcp://*:" + to_string(bound_port(occupied));

            ZMQSenderChannel collides;
            ASSERT_THROW(collides.bind(taken), zmq::error_t);
            ASSERT_FALSE(collides.is_connected());
        }

        {
            ZMQReceiverChannel bad_address;
            ASSERT_THROW(bad_address.connect("this is not an endpoint"), zmq::error_t);
            ASSERT_FALSE(bad_address.is_connected());
        }

        SUCCEED() << "both channels were destroyed without hanging";
    }

    TEST_F(ZMQChannelTests, ReceiveOperationReturnsNullOnInvalidInput)
    {
        // receive_operation wraps receive_network_operation and must propagate a nullptr
        // return rather than dereferencing it. This is a regression test: the wrapper once
        // accessed `receive_network_operation(...)->sop` unconditionally, so every path that
        // returns nullptr (missing context, empty non-blocking queue, malformed input) crashed
        // instead of failing cleanly. Here we exercise two such paths and require nullptr.

        // Use a dedicated socket pair so lingering queue state from the shared server()/client()
        // instances cannot affect the result.
        ZMQSenderChannel svr;
        ZMQReceiverChannel clt;
        svr.bind(any_port_bind_address());
        clt.connect(connect_address(svr));

        // The default expected type sop_unknown requires a SEALContext; passing nullptr makes
        // receive_network_operation return nullptr before it reads any message.
        ASSERT_EQ(nullptr, svr.receive_operation(nullptr));

        // sop_parms needs no context, so this reaches the (non-blocking) receive, which returns
        // nullptr because no message has been queued.
        ASSERT_EQ(nullptr, svr.receive_operation(nullptr, SenderOperationType::sop_parms));
    }

    TEST_F(ZMQChannelTests, WrongFrameCountIsReportedAsFailureRatherThanThrown)
    {
        // A peer controls how many frames it puts in a message, so a frame count that does not
        // match what the receiving function expects is ordinary hostile input. Throwing on it
        // would let any peer unwind the stack of whichever thread happened to read the message;
        // in the sender that thread runs the dispatch loop for every client. The count is
        // reported the same way as any other unreadable message instead: null, plus a failure
        // the caller can see.
        ZMQSenderChannel svr;
        ZMQReceiverChannel clt;
        svr.bind(any_port_bind_address());
        clt.connect(connect_address(svr));

        // A response carries one more frame than an operation, so sending one where an
        // operation is expected produces a message of the wrong length without any hand-built
        // ZeroMQ frames.
        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        clt.send(unique_ptr<SenderOperationResponse>(std::move(rsop_parms)));

        unique_ptr<ZMQSenderOperation> nsop;
        ASSERT_NO_THROW(nsop = svr.receive_network_operation(get_context()->seal_context(), true));
        ASSERT_EQ(nullptr, nsop);
        ASSERT_TRUE(svr.receive_failed());
    }

    TEST_F(ZMQChannelTests, ManyFramedMessageIsRejectedAndTheChannelKeepsServing)
    {
        // A peer chooses how many frames it packs into one message, so an absurd count is
        // ordinary hostile input. It must be rejected on frame count like any other malformed
        // message, and the channel must go on serving afterwards.
        //
        // Note what this does NOT establish. ZeroMQ's message size limit applies to each frame
        // separately and its high-water mark counts whole messages, so neither bounds the frame
        // count, and ZeroMQ buffers a message in full before offering it to the application.
        // The memory is therefore already spent by the time any APSI code runs, and no check
        // here can prevent that. Mitigating it means bounding concurrent connections at the
        // network layer, since the cost scales with concurrent peers and not with total traffic.
        ZMQSenderChannel svr;
        svr.bind(any_port_bind_address());

        zmq::context_t ctx;
        zmq::socket_t peer(ctx, zmq::socket_type::dealer);
        peer.set(zmq::sockopt::linger, 0);
        peer.connect(connect_address(svr));

        zmq::multipart_t oversized;
        for (size_t i = 0; i < 500; i++) {
            oversized.addstr("");
        }
        ASSERT_TRUE(oversized.send(peer));

        unique_ptr<ZMQSenderOperation> nsop;
        ASSERT_NO_THROW(nsop = svr.receive_network_operation(get_context()->seal_context(), true));
        ASSERT_EQ(nullptr, nsop);
        ASSERT_TRUE(svr.receive_failed());

        // An honest request sent afterwards is read as a request, not as the tail of the
        // message that was thrown away.
        ZMQReceiverChannel clt;
        clt.connect(connect_address(svr));
        clt.send(unique_ptr<SenderOperation>(make_unique<SenderOperationParms>()));

        unique_ptr<ZMQSenderOperation> honest;
        ASSERT_NO_THROW(
            honest = svr.receive_network_operation(get_context()->seal_context(), true));
        ASSERT_NE(nullptr, honest);
        ASSERT_EQ(SenderOperationType::sop_parms, honest->sop->type());
    }

    TEST_F(ZMQChannelTests, ResponseOfTheWrongTypeIsReportedAsFailure)
    {
        // The receiver waits for a response by looping until one arrives. A response of a type
        // it did not ask for is consumed and discarded, so unless the discard is reported the
        // loop waits forever for a message that has already come and gone.
        ZMQSenderChannel svr;
        ZMQReceiverChannel clt;
        svr.bind(any_port_bind_address());
        clt.connect(connect_address(svr));

        clt.send(unique_ptr<SenderOperation>(make_unique<SenderOperationParms>()));
        auto nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_NE(nullptr, nsop);

        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        auto nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = nsop->client_id;
        nrsop->sop_response = std::move(rsop_parms);
        svr.send(std::move(nrsop));

        ASSERT_EQ(nullptr, clt.receive_response(SenderOperationType::sop_oprf));
        ASSERT_TRUE(clt.receive_failed());
    }

    TEST_F(ZMQChannelTests, SendingToAPeerThatIsNotThereFails)
    {
        // A ROUTER hands a message to the pipe named by its first frame. Asked for a peer it
        // does not have, it must say so: a sender announces how many result packages a receiver
        // should expect, and a package that went nowhere leaves that receiver waiting for one
        // it will never get, with nothing on either side reporting a problem.
        ZMQSenderChannel svr;
        svr.bind(any_port_bind_address());

        auto rp = make_unique<ResultPackage>();
        rp->compr_mode = seal::Serialization::compr_mode_default;
        rp->bundle_idx = 0;
        rp->nonce_byte_count = 0;
        rp->label_byte_count = 0;
        Ciphertext ct;
        get_context()->encryptor()->encrypt_zero_symmetric(ct);
        rp->psi_result = std::move(ct);

        auto nrp = make_unique<ZMQResultPackage>();
        nrp->client_id = vector<unsigned char>{ 'A', 'b', 's', 'e', 'n', 't' };
        nrp->rp = std::move(rp);

        ASSERT_THROW(svr.send(std::move(nrp)), runtime_error);
    }

    namespace {
        /**
        The shipped channels queue tens of thousands of messages before a peer that has stopped
        reading is noticed, which is the right figure in production and far too many to drive
        through a test. These shrink the queue and the timeout so that the same code path is
        reached in a fraction of a second.
        */
        class SmallQueueSenderChannel : public ZMQSenderChannel {
        protected:
            void set_socket_options(zmq::socket_t *socket) override
            {
                ZMQSenderChannel::set_socket_options(socket);
                socket->set(zmq::sockopt::sndhwm, 4);
                socket->set(zmq::sockopt::sndtimeo, 200);

                // This test leaves messages queued for a peer that will never read them, and
                // closing a socket waits out its linger for exactly those. The shipped sender
                // waits a minute, which is right when the queue holds an answer somebody is
                // still waiting for and is a minute of dead test otherwise.
                socket->set(zmq::sockopt::linger, 0);
            }
        };

        class SmallQueueReceiverChannel : public ZMQReceiverChannel {
        protected:
            void set_socket_options(zmq::socket_t *socket) override
            {
                ZMQReceiverChannel::set_socket_options(socket);
                socket->set(zmq::sockopt::rcvhwm, 1);
            }
        };
    } // namespace

    TEST_F(ZMQChannelTests, SendingToAPeerThatHasStoppedReadingFails)
    {
        // The other way a ROUTER discards a message: the peer is connected but has not read for
        // long enough to fill its queue. This is a different path from an absent peer -- ZeroMQ
        // reports it by returning nothing rather than by throwing -- and it is the one a
        // receiver reaches by simply going away mid-query while its connection stays up.
        SmallQueueSenderChannel svr;
        SmallQueueReceiverChannel clt;
        svr.bind(any_port_bind_address());
        clt.connect(connect_address(svr));

        // One request, so that the sender learns who the peer is. The receiver reads nothing
        // after this.
        clt.send(unique_ptr<SenderOperation>(make_unique<SenderOperationParms>()));
        auto nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_NE(nullptr, nsop);

        Ciphertext ct;
        get_context()->encryptor()->encrypt_zero_symmetric(ct);

        bool threw = false;
        for (size_t i = 0; i < 1000 && !threw; i++) {
            auto rp = make_unique<ResultPackage>();
            rp->bundle_idx = 0;
            rp->label_byte_count = 0;
            rp->nonce_byte_count = 0;
            rp->psi_result = ct;

            auto nrp = make_unique<ZMQResultPackage>();
            nrp->client_id = nsop->client_id;
            nrp->rp = std::move(rp);

            try {
                svr.send(std::move(nrp));
            } catch (const runtime_error &) {
                threw = true;
            }
        }

        ASSERT_TRUE(threw);
    }

    TEST_F(ZMQChannelTests, ClientServerFullSession)
    {
        ZMQSenderChannel svr;
        ZMQReceiverChannel clt;

        svr.bind(any_port_bind_address());
        clt.connect(connect_address(svr));

        thread clientth([&clt] {
            this_thread::sleep_for(50ms);

            auto sop_parms = make_unique<SenderOperationParms>();
            unique_ptr<SenderOperation> sop = make_unique<SenderOperationParms>();

            // Send a Parms operation
            clt.send(std::move(sop));

            // Fill a data buffer
            vector<unsigned char> oprf_data(256);
            for (size_t i = 0; i < oprf_data.size(); i++) {
                oprf_data[i] = static_cast<unsigned char>(i);
            }

            auto sop_oprf = make_unique<SenderOperationOPRF>();
            sop_oprf->data = oprf_data;
            sop = std::move(sop_oprf);

            // Send an OPRF operation with some dummy data
            clt.send(std::move(sop));

            auto sop_query = make_unique<SenderOperationQuery>();
            auto relin_keys = get_context()->relin_keys();
            sop_query->relin_keys = *relin_keys;
            sop_query->data[0].emplace_back(get_context()->encryptor()->encrypt_zero_symmetric());
            sop_query->data[123].emplace_back(get_context()->encryptor()->encrypt_zero_symmetric());
            sop = std::move(sop_query);

            // Send a query operation with some dummy data
            clt.send(std::move(sop));

            // Next, try receiving an OPRF response; this is incorrect so should return nullptr
            ASSERT_EQ(nullptr, clt.receive_response(SenderOperationType::sop_oprf));

            // Receive correctly the parms response
            auto rsop = clt.receive_response(SenderOperationType::sop_parms);
            unique_ptr<SenderOperationResponseParms> rsop_parms;
            rsop_parms.reset(dynamic_cast<SenderOperationResponseParms *>(rsop.release()));

            // We received valid parameters
            ASSERT_EQ(get_params()->item_bit_count(), rsop_parms->params->item_bit_count());

            // Receive an OPRF response
            rsop = clt.receive_response(SenderOperationType::sop_oprf);
            unique_ptr<SenderOperationResponseOPRF> rsop_oprf;
            rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(rsop.release()));

            ASSERT_EQ(256, rsop_oprf->data.size());
            for (size_t i = 0; i < rsop_oprf->data.size(); i++) {
                ASSERT_EQ(static_cast<char>(rsop_oprf->data[i]), static_cast<char>(i));
            }

            // Receive a query response
            rsop = clt.receive_response(SenderOperationType::sop_query);
            unique_ptr<SenderOperationResponseQuery> rsop_query;
            rsop_query.reset(dynamic_cast<SenderOperationResponseQuery *>(rsop.release()));

            ASSERT_EQ(2, rsop_query->package_count);

            // Receive two packages
            auto rp = clt.receive_result(get_context()->seal_context());
            ASSERT_EQ(0, rp->bundle_idx);
            ASSERT_EQ(0, rp->label_byte_count);
            ASSERT_EQ(0, rp->nonce_byte_count);
            ASSERT_TRUE(rp->label_result.empty());

            rp = clt.receive_result(get_context()->seal_context());
            ASSERT_EQ(123, rp->bundle_idx);
            ASSERT_EQ(80, rp->label_byte_count);
            ASSERT_EQ(4, rp->nonce_byte_count);
            ASSERT_EQ(1, rp->label_result.size());
        });

        // Receive a parms operation
        auto sop_parms = make_unique<SenderOperationParms>();

        // It's important to receive this as a SenderNetworkOperation, otherwise we can't get the
        // client_id for ZeroMQ internal routing.
        auto nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_parms, nsop->sop->type());
        ASSERT_FALSE(nsop->client_id.empty());
        auto client_id = nsop->client_id;

        // Receive an OPRF operation
        nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_oprf, nsop->sop->type());
        ASSERT_EQ(client_id, nsop->client_id);
        unique_ptr<SenderOperationOPRF> sop_oprf;
        sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(nsop->sop.release()));

        ASSERT_EQ(256, sop_oprf->data.size());
        for (size_t i = 0; i < sop_oprf->data.size(); i++) {
            ASSERT_EQ(static_cast<char>(sop_oprf->data[i]), static_cast<char>(i));
        }

        // Receive a query operation
        nsop = svr.receive_network_operation(get_context()->seal_context(), true);
        ASSERT_EQ(SenderOperationType::sop_query, nsop->sop->type());
        ASSERT_EQ(client_id, nsop->client_id);
        unique_ptr<SenderOperationQuery> sop_query;
        sop_query.reset(dynamic_cast<SenderOperationQuery *>(nsop->sop.release()));

        // Are we able to extract the relinearization keys?
        ASSERT_NO_THROW(auto rlk = sop_query->relin_keys.extract_if_local());

        // Check for query ciphertexts
        ASSERT_EQ(2, sop_query->data.size());

        ASSERT_FALSE(sop_query->data.at(0).empty());
        ASSERT_EQ(1, sop_query->data[0].size());
        auto query_ct0 = sop_query->data[0][0].extract_if_local();

        ASSERT_FALSE(sop_query->data.at(123).empty());
        ASSERT_EQ(1, sop_query->data[123].size());
        auto query_ct123 = sop_query->data[123][0].extract_if_local();

        // Create a parms response
        auto rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());

        // Actually we need a ZMQSenderOperationResponse for ZeroMQ; we'll need to use the correct
        // client_id here.
        auto nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = std::move(rsop_parms);

        // Try sending the parameters; the receiver is incorrectly expecting an OPRF response so it
        // will fail to receive this package. We'll have to send it twice so that on the second time
        // it gets the response correctly.
        svr.send(std::move(nrsop));

        // Send again so receiver actually gets it
        rsop_parms = make_unique<SenderOperationResponseParms>();
        rsop_parms->params = make_unique<PSIParams>(*get_params());
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = std::move(rsop_parms);
        svr.send(std::move(nrsop));

        // Create an OPRF response and response with the same data we received
        auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
        rsop_oprf->data = sop_oprf->data;
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = std::move(rsop_oprf);
        svr.send(std::move(nrsop));

        // Create a query response; we will return two packages
        auto rsop_query = make_unique<SenderOperationResponseQuery>();
        rsop_query->package_count = 2;
        nrsop = make_unique<ZMQSenderOperationResponse>();
        nrsop->client_id = client_id;
        nrsop->sop_response = std::move(rsop_query);
        svr.send(std::move(nrsop));

        // Finally send two ZMQResultPackages
        auto rp = make_unique<ResultPackage>();
        rp->bundle_idx = 0;
        rp->label_byte_count = 0;
        rp->nonce_byte_count = 0;
        rp->psi_result = query_ct0;
        auto nrp = make_unique<ZMQResultPackage>();
        nrp->client_id = client_id;
        nrp->rp = std::move(rp);
        svr.send(std::move(nrp));

        rp = make_unique<ResultPackage>();
        rp->bundle_idx = 123;
        rp->label_byte_count = 80;
        rp->nonce_byte_count = 4;
        rp->psi_result = query_ct123;
        rp->label_result.emplace_back(query_ct123);
        nrp = make_unique<ZMQResultPackage>();
        nrp->client_id = client_id;
        nrp->rp = std::move(rp);
        svr.send(std::move(nrp));

        clientth.join();
    }

    TEST_F(ZMQChannelTests, MultipleClients)
    {
        atomic<bool> finished{ false };

        // Bound here rather than inside the server thread so that the clients can be told which
        // port the operating system handed out. Only the server thread touches the channel once
        // it starts, and the bind happens before that.
        ZMQSenderChannel sender;
        sender.bind(any_port_bind_address());
        const string server_address = connect_address(sender);

        thread serverth([&finished, &sender] {
            while (!finished) {
                unique_ptr<ZMQSenderOperation> sop =
                    sender.receive_network_operation(get_context()->seal_context());
                if (!sop) {
                    this_thread::sleep_for(50ms);
                    continue;
                }

                ASSERT_EQ(SenderOperationType::sop_oprf, sop->sop->type());
                unique_ptr<SenderOperationOPRF> sop_oprf;
                sop_oprf.reset(dynamic_cast<SenderOperationOPRF *>(sop->sop.release()));
                auto client_id = sop->client_id;

                // Return the same data we received
                auto rsop_oprf = make_unique<SenderOperationResponseOPRF>();
                rsop_oprf->data = sop_oprf->data;
                auto sopr = make_unique<ZMQSenderOperationResponse>();
                sopr->client_id = client_id;
                sopr->sop_response = std::move(rsop_oprf);

                // Send
                sender.send(std::move(sopr));
            }
        });

        vector<thread> clients(5);
        for (auto &client : clients) {
            client = thread([&server_address]() {
                ZMQReceiverChannel recv;

                recv.connect(server_address);

                for (uint32_t k = 0; k < 5; k++) {
                    vector<unsigned char> oprf_data(256);
                    for (size_t j = 0; j < oprf_data.size(); j++) {
                        oprf_data[j] = static_cast<unsigned char>(j);
                    }

                    auto sop_oprf = make_unique<SenderOperationOPRF>();
                    sop_oprf->data = oprf_data;
                    unique_ptr<SenderOperation> sop = std::move(sop_oprf);
                    recv.send(std::move(sop));

                    auto sopr = recv.receive_response();
                    ASSERT_NE(nullptr, sopr);
                    unique_ptr<SenderOperationResponseOPRF> rsop_oprf;
                    rsop_oprf.reset(dynamic_cast<SenderOperationResponseOPRF *>(sopr.release()));

                    // Check that we receive what we sent
                    ASSERT_EQ(256, rsop_oprf->data.size());
                    for (size_t j = 0; j < rsop_oprf->data.size(); j++) {
                        ASSERT_EQ(
                            static_cast<unsigned char>(rsop_oprf->data[j]),
                            static_cast<unsigned char>(j));
                    }
                }
            });
        }

        for (auto &client : clients) {
            client.join();
        }

        finished = true;
        serverth.join();
    }
} // namespace APSITests
