// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/log.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/streambuf.h"

// ZeroMQ
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include "zmq.hpp"
#include "zmq_addon.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace zmq;

namespace apsi {
    using namespace util;

    namespace network {
        namespace {
            // ZeroMQ waits indefinitely wherever it waits at all. The bounds below replace that,
            // so that nothing here can be held forever by what a peer does.

            // A blocking receive gives up and returns empty-handed after this. It is a poll
            // interval rather than a deadline: a caller still waiting legitimately just
            // receives again, having had the chance to re-examine its own state in between.
            constexpr int receive_poll_interval_ms = 1000;

            // How long closing a socket waits for messages it has queued but not yet handed
            // over. A receiver has only its own small request outstanding, and that request is
            // worthless once it has stopped waiting for the answer.
            constexpr int receiver_linger_ms = 1000;

            // A sender's queue can hold the entire answer to a query instead, which may still
            // be streaming out when the sender is asked to stop. Cutting that short truncates a
            // legitimate response, so this is generous enough to push one over a slow link.
            constexpr int sender_linger_ms = 60000;

            // How long a send waits before reporting failure. The sender's high water mark
            // leaves a wide cushion first, so reaching this means a peer has stopped reading
            // rather than fallen behind.
            constexpr int send_timeout_ms = 30000;

            // How many messages ZeroMQ may hold for one peer before a send to it blocks, and
            // then fails once send_timeout_ms is up. The sender's outbound queue and the
            // receiver's inbound queue are separate and each bounded by this, so the path
            // between the two admits more than one queue's worth.
            //
            // This is backpressure, not capacity for an answer. A query sends one result package
            // per bin bundle and may run to far more packages than this: the receiver drains the
            // queue while the sender is still evaluating the rest, and a full queue makes a send
            // wait rather than discard, so a long answer does not need a deep queue.
            //
            // What the number bounds is the serialized payload ZeroMQ holds for a peer that has
            // stopped reading, since it keeps a queued message until that peer reads it rather
            // than until the query ends, and keeps a queue per peer. A result package measures
            // 443 KB at the largest shipped parameter set and 97 KB at a typical one, which puts
            // one stalled peer on the order of a hundred megabytes where a high water mark of
            // 70000 allowed tens of gigabytes. It does not bound what the sender itself holds:
            // a result computed but not yet handed over is the sender's own memory.
            //
            // The value is a conservative operating choice rather than one the protocol dictates.
            // A peer that stalls long enough to fill the queue and keep it full for
            // send_timeout_ms loses the query, and learns of it only by running out its own
            // deadline, because nothing tells it that the answer it was promised was abandoned.
            constexpr int result_package_hwm = 256;

            template <typename T>
            size_t load_from_string(string data, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream);
            }

            template <typename T>
            // context is taken by value to match the by-value SEALContext convention of the
            // Channel interface this helper serves.
            // NOLINTNEXTLINE(performance-unnecessary-value-param)
            size_t load_from_string(string data, shared_ptr<SEALContext> context, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream, std::move(context));
            }

            template <typename T>
            size_t save_to_message(const T &obj, multipart_t &msg)
            {
                stringstream ss;
                size_t size = obj.save(ss);
                msg.addstr(ss.str());
                return size;
            }

            template <>
            size_t save_to_message(const vector<unsigned char> &obj, multipart_t &msg)
            {
                msg.addmem(obj.data(), obj.size());
                return obj.size();
            }

            vector<unsigned char> get_client_id(const multipart_t &msg)
            {
                size_t client_id_size = msg[0].size();
                vector<unsigned char> client_id(client_id_size);
                copy_bytes(msg[0].data(), client_id_size, client_id.data());
                return client_id;
            }
        } // namespace

        ZMQChannel::ZMQChannel() : context_(make_unique<context_t>())
        {}

        ZMQChannel::~ZMQChannel()
        {
            try {
                if (is_connected()) {
                    disconnect();
                }
            } catch (...) {
                try {
                    APSI_LOG_DEBUG("Failed to disconnect socket during ZMQChannel destruction");
                } catch (...) { // NOLINT(bugprone-empty-catch): a destructor must not throw
                }
            }
        }

        void ZMQChannel::bind(const string &end_point)
        {
            throw_if_connected();

            try {
                get_socket()->bind(end_point);

                // Record what ZeroMQ actually bound rather than what was asked for. A port of 0
                // asks the operating system to pick a free one, and this is the only way to find
                // out which. Assigning only after the bind succeeds also matters: a channel whose
                // bind threw must not be left looking connected, or a caller that retries on
                // is_connected() will skip the retry and go on to use an unbound socket.
                end_point_ = get_socket()->get(sockopt::last_endpoint);
            } catch (const zmq::error_t &) {
                APSI_LOG_ERROR("ZeroMQ failed to bind socket to endpoint " << end_point);
                throw;
            }
        }

        void ZMQChannel::connect(const string &end_point)
        {
            throw_if_connected();

            try {
                get_socket()->connect(end_point);
                end_point_ = end_point;
            } catch (const zmq::error_t &) {
                APSI_LOG_ERROR("ZeroMQ failed to connect socket to endpoint " << end_point);
                throw;
            }
        }

        void ZMQChannel::disconnect()
        {
            throw_if_not_connected();

            // Cannot use get_socket() in disconnect(): this function is called by the destructor
            // and get_socket() is virtual. Instead just do this.
            if (nullptr != socket_) {
                socket_->close();
            }
            if (context_) {
                context_->shutdown();
                context_->close();
            }

            end_point_ = "";
            socket_.reset();
            context_.reset();
        }

        void ZMQChannel::throw_if_not_connected() const
        {
            if (!is_connected()) {
                APSI_LOG_ERROR("Socket is not connected");
                throw runtime_error("socket is not connected");
            }
        }

        void ZMQChannel::throw_if_connected() const
        {
            if (is_connected()) {
                APSI_LOG_ERROR("Socket is already connected");
                throw runtime_error("socket is already connected");
            }
        }

        void ZMQChannel::send(unique_ptr<SenderOperation> sop)
        {
            throw_if_not_connected();

            // Need to have the SenderOperation package
            if (!sop) {
                APSI_LOG_ERROR("Failed to send operation: operation data is missing");
                throw invalid_argument("operation data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop->type();
            APSI_LOG_DEBUG(
                "Sending operation of type " << sender_operation_type_str(sop_header.type));

            size_t bytes_sent = 0;

            multipart_t msg;

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSI_LOG_DEBUG(
                "Sent an operation of type " << sender_operation_type_str(sop_header.type) << " ("
                                             << bytes_sent << " bytes)");
        }

        unique_ptr<ZMQSenderOperation> ZMQChannel::receive_network_operation(
            shared_ptr<SEALContext> context, bool wait_for_message, SenderOperationType expected)
        {
            throw_if_not_connected();

            bool valid_context = context && context->parameters_set();
            if (!valid_context && (expected == SenderOperationType::sop_unknown ||
                                   expected == SenderOperationType::sop_query)) {
                // Cannot receive unknown or query operations without a valid SEALContext
                APSI_LOG_ERROR(
                    "Cannot receive an operation of type "
                    << sender_operation_type_str(expected)
                    << "; SEALContext is missing or invalid");
                set_receive_failed();
                return nullptr;
            }

            size_t old_bytes_received = bytes_received_;

            multipart_t msg;
            if (!receive_message(msg, wait_for_message)) {
                // No message yet. Don't log anything.
                return nullptr;
            }

            // Should have client_id, SenderOperationHeader, and SenderOperation.
            if (msg.size() != 3) {
                APSI_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 3 parts");
                set_receive_failed();
                return nullptr;
            }

            // First extract the client_id; this is the first part of the message
            vector<unsigned char> client_id = get_client_id(msg);

            // Second part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try {
                bytes_received_ += load_from_string(msg[1].to_string(), sop_header);
            } catch (const runtime_error &) {
                // Invalid header
                APSI_LOG_ERROR("Failed to receive a valid header");
                set_receive_failed();
                return nullptr;
            } catch (const exception &ex) {
                // Any other failure, e.g. allocation failure from an oversized size prefix
                APSI_LOG_ERROR("Failed to receive a valid header: " << ex.what());
                set_receive_failed();
                return nullptr;
            }

            if (!same_serialization_version(sop_header.version)) {
                // Check that the serialization version numbers match
                APSI_LOG_ERROR(
                    "Received header indicates a serialization version number ("
                    << sop_header.version
                    << ") incompatible with the current serialization version number ("
                    << apsi_serialization_version << ")");
                set_receive_failed();
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
                // Unexpected operation
                APSI_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << sender_operation_type_str(sop_header.type));
                set_receive_failed();
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<SenderOperation> sop = nullptr;

            try {
                switch (sop_header.type) {
                case SenderOperationType::sop_parms:
                    sop = make_unique<SenderOperationParms>();
                    bytes_received = load_from_string(msg[2].to_string(), *sop);
                    bytes_received_ += bytes_received;
                    break;
                case SenderOperationType::sop_oprf:
                    sop = make_unique<SenderOperationOPRF>();
                    bytes_received = load_from_string(msg[2].to_string(), *sop);
                    bytes_received_ += bytes_received;
                    break;
                case SenderOperationType::sop_query:
                    sop = make_unique<SenderOperationQuery>();
                    bytes_received = load_from_string(msg[2].to_string(), std::move(context), *sop);
                    bytes_received_ += bytes_received;
                    break;
                default:
                    // Invalid operation
                    APSI_LOG_ERROR(
                        "Received header indicates an invalid operation type "
                        << sender_operation_type_str(sop_header.type));
                    set_receive_failed();
                    return nullptr;
                }
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            } catch (const exception &ex) {
                // Any other failure, e.g. allocation failure from an oversized size prefix
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            }

            // Loaded successfully; set up ZMQSenderOperation package
            auto n_sop = make_unique<ZMQSenderOperation>();
            n_sop->client_id = std::move(client_id);
            n_sop->sop = std::move(sop);

            APSI_LOG_DEBUG(
                "Received an operation of type " << sender_operation_type_str(sop_header.type)
                                                 << " (" << bytes_received_ - old_bytes_received
                                                 << " bytes)");

            return n_sop;
        }

        unique_ptr<SenderOperation> ZMQChannel::receive_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            // receive_network_operation returns nullptr on every error path (malformed header,
            // version mismatch, unexpected/invalid operation type, parse exception).
            auto n_sop = receive_network_operation(std::move(context), expected);
            if (!n_sop) {
                return nullptr;
            }
            return std::move(n_sop->sop);
        }

        void ZMQChannel::send(unique_ptr<ZMQSenderOperationResponse> sop_response)
        {
            throw_if_not_connected();

            // Need to have the SenderOperationResponse package
            if (!sop_response) {
                APSI_LOG_ERROR("Failed to send response: response data is missing");
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop_response->sop_response->type();
            APSI_LOG_DEBUG(
                "Sending response of type " << sender_operation_type_str(sop_header.type));

            size_t bytes_sent = 0;

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(sop_response->client_id, msg);

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop_response->sop_response, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSI_LOG_DEBUG(
                "Sent an operation of type " << sender_operation_type_str(sop_header.type) << " ("
                                             << bytes_sent << " bytes)");
        }

        void ZMQChannel::send(unique_ptr<SenderOperationResponse> sop_response)
        {
            // Leave the client_id empty
            auto n_sop_response = make_unique<ZMQSenderOperationResponse>();
            n_sop_response->sop_response = std::move(sop_response);

            send(std::move(n_sop_response));
        }

        unique_ptr<SenderOperationResponse> ZMQChannel::receive_response(
            SenderOperationType expected)
        {
            throw_if_not_connected();

            size_t old_bytes_received = bytes_received_;

            multipart_t msg;
            if (!receive_message(msg)) {
                // No message yet. Don't log anything.
                return nullptr;
            }

            // Should have SenderOperationHeader and SenderOperationResponse.
            if (msg.size() != 2) {
                APSI_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 2 parts");
                set_receive_failed();
                return nullptr;
            }

            // First part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try {
                bytes_received_ += load_from_string(msg[0].to_string(), sop_header);
            } catch (const runtime_error &) {
                // Invalid header
                APSI_LOG_ERROR("Failed to receive a valid header");
                set_receive_failed();
                return nullptr;
            } catch (const exception &ex) {
                // Any other failure, e.g. allocation failure from an oversized size prefix
                APSI_LOG_ERROR("Failed to receive a valid header: " << ex.what());
                set_receive_failed();
                return nullptr;
            }

            if (!same_serialization_version(sop_header.version)) {
                // Check that the serialization version numbers match
                APSI_LOG_ERROR(
                    "Received header indicates a serialization version number "
                    << sop_header.version
                    << " incompatible with the current serialization version number "
                    << apsi_serialization_version);
                set_receive_failed();
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
                // Unexpected operation
                APSI_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << sender_operation_type_str(sop_header.type));
                set_receive_failed();
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<SenderOperationResponse> sop_response = nullptr;

            try {
                switch (sop_header.type) {
                case SenderOperationType::sop_parms:
                    sop_response = make_unique<SenderOperationResponseParms>();
                    bytes_received = load_from_string(msg[1].to_string(), *sop_response);
                    bytes_received_ += bytes_received;
                    break;
                case SenderOperationType::sop_oprf:
                    sop_response = make_unique<SenderOperationResponseOPRF>();
                    bytes_received = load_from_string(msg[1].to_string(), *sop_response);
                    bytes_received_ += bytes_received;
                    break;
                case SenderOperationType::sop_query:
                    sop_response = make_unique<SenderOperationResponseQuery>();
                    bytes_received = load_from_string(msg[1].to_string(), *sop_response);
                    bytes_received_ += bytes_received;
                    break;
                default:
                    // Invalid operation
                    APSI_LOG_ERROR(
                        "Received header indicates an invalid operation type "
                        << sender_operation_type_str(sop_header.type));
                    set_receive_failed();
                    return nullptr;
                }
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
                set_receive_failed();
                return nullptr;
            } catch (const exception &ex) {
                // Any other failure, e.g. allocation failure from an oversized size prefix
                APSI_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
                set_receive_failed();
                return nullptr;
            }

            // Loaded successfully
            APSI_LOG_DEBUG(
                "Received a response of type " << sender_operation_type_str(sop_header.type) << " ("
                                               << bytes_received_ - old_bytes_received
                                               << " bytes)");

            return sop_response;
        }

        void ZMQChannel::send(unique_ptr<ZMQResultPackage> rp)
        {
            throw_if_not_connected();

            // Need to have the ResultPackage
            if (!rp) {
                APSI_LOG_ERROR("Failed to send result package: result package data is missing");
                throw invalid_argument("result package data is missing");
            }

            APSI_LOG_DEBUG(
                "Sending result package ("
                << "has matching data: " << (rp->rp->psi_result ? "yes" : "no") << "; "
                << "label byte count: " << rp->rp->label_byte_count << "; "
                << "nonce byte count: " << rp->rp->nonce_byte_count << "; "
                << "has label data: " << (!rp->rp->label_result.empty() ? "yes" : "no") << ")");

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(rp->client_id, msg);

            size_t bytes_sent = save_to_message(*rp->rp, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSI_LOG_DEBUG("Sent a result package (" << bytes_sent << " bytes)");
        }

        void ZMQChannel::send(unique_ptr<ResultPackage> rp)
        {
            // Leave the client_id empty
            auto n_rp = make_unique<ZMQResultPackage>();
            n_rp->rp = std::move(rp);

            send(std::move(n_rp));
        }

        unique_ptr<ResultPackage> ZMQChannel::receive_result(shared_ptr<SEALContext> context)
        {
            throw_if_not_connected();

            bool valid_context = context && context->parameters_set();
            if (!valid_context) {
                // Cannot receive a result package without a valid SEALContext
                APSI_LOG_ERROR(
                    "Cannot receive a result package; SEALContext is missing or invalid");
                set_receive_failed();
                return nullptr;
            }

            multipart_t msg;
            if (!receive_message(msg)) {
                // No message yet. Don't log anything.
                return nullptr;
            }

            // Should have only one part: ResultPackage.
            if (msg.size() != 1) {
                APSI_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 1 part");
                set_receive_failed();
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try {
                bytes_received = load_from_string(msg[0].to_string(), std::move(context), *rp);
                bytes_received_ += bytes_received;
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            } catch (const exception &ex) {
                // Any other failure, e.g. allocation failure from an oversized size prefix
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                set_receive_failed();
                return nullptr;
            }

            // Loaded successfully
            APSI_LOG_DEBUG("Received a result package (" << bytes_received << " bytes)");

            return rp;
        }

        bool ZMQChannel::receive_message(multipart_t &msg, bool wait_for_message)
        {
            lock_guard<mutex> lock(receive_mutex_);

            msg.clear();
            recv_flags receive_flags = wait_for_message ? recv_flags::none : recv_flags::dontwait;

            // A false return means no message was available: either the caller asked not to
            // wait, or a blocking receive hit the socket's receive timeout. Genuine socket
            // errors surface as zmq::error_t from recv itself. The timeout is what lets a
            // blocking caller regain control periodically, so it can notice that the exchange
            // it is waiting on has already failed on another thread.
            //
            // A message is delivered to a reader only once every one of its frames has arrived,
            // so an empty return can only land on a message boundary and never leaves a
            // half-read message behind to be mistaken for the start of the next one.
            return msg.recv(*get_socket(), static_cast<int>(receive_flags));
        }

        void ZMQChannel::send_message(multipart_t &msg)
        {
            lock_guard<mutex> lock(send_mutex_);

            // Two failure signals have to reach the caller. ZeroMQ throws when it has no route
            // to the peer, and returns nothing when it could not hand the message over before
            // the send timeout expired. Neither is distinguishable to anything upstream, so
            // both are reported the same way.
            //
            // A send that does not fail means ZeroMQ accepted the message for a peer it
            // believes in, not that the peer received it. A message handed to a pipe that dies
            // immediately afterwards is still lost silently, which no setting here can change.
            // What this does rule out is a message discarded for a peer already known to be
            // gone, or for one whose queue was already full.
            send_result_t result;
            try {
                result = send_multipart(*get_socket(), msg, send_flags::none);
            } catch (const zmq::error_t &ex) {
                APSI_LOG_ERROR("Failed to send message: " << ex.what());
                throw runtime_error(string("failed to send message: ") + ex.what());
            }

            if (!result.has_value()) {
                APSI_LOG_ERROR("Failed to send message: timed out under backpressure");
                throw runtime_error("failed to send message: timed out under backpressure");
            }
        }

        unique_ptr<socket_t> &ZMQChannel::get_socket()
        {
            if (nullptr == socket_) {
                socket_ = make_unique<socket_t>(*context_, get_socket_type());
                set_socket_options(socket_.get());
            }

            return socket_;
        }

        zmq::socket_type ZMQReceiverChannel::get_socket_type()
        {
            return zmq::socket_type::dealer;
        }

        void ZMQReceiverChannel::set_socket_options(socket_t *socket)
        {
            // How far ahead a sender may get while this receiver is still working through what
            // has arrived. A DEALER whose queue is full stops reading rather than discarding,
            // so this throttles the sender instead of losing anything. See
            // result_package_hwm for why the depth is what it is.
            socket->set(sockopt::rcvhwm, result_package_hwm);

            // The receiver runs several result workers over this one socket, serialized by the
            // receive mutex. Without a bound, a worker could hold that mutex parked forever on
            // a package the sender never sends, with its siblings and the join that waits for
            // them stuck behind it.
            socket->set(sockopt::rcvtimeo, receive_poll_interval_ms);

            // Bound a send too, though it says nothing about whether a sender is there: a
            // DEALER queues into a pipe it creates at connect time, so a request goes out
            // whether or not anything is listening.
            socket->set(sockopt::sndtimeo, send_timeout_ms);

            // Reject an inbound frame larger than INT32_MAX, the FlatBuffers verifier's own
            // maximum, so anything bigger would fail verification later anyway.
            //
            // This bounds one frame, not how many frames a message may hold, and nothing here
            // can bound that: ZeroMQ assembles a message in full before offering it to a
            // reader. That exposure grows with the number of concurrent peers rather than with
            // traffic, so it belongs at the network layer.
            // NOLINTNEXTLINE(readability-redundant-parentheses): windows.h defines max
            constexpr int64_t max_message_size = (numeric_limits<int32_t>::max)();
            socket->set(sockopt::maxmsgsize, max_message_size);

            // What lets a receiver that has given up on a silent sender actually exit.
            socket->set(sockopt::linger, receiver_linger_ms);

            string buf;
            buf.resize(32);
            secure_random_bytes(buf.data(), buf.size());
            // make sure first byte is _not_ zero, as that has a special meaning for ZeroMQ
            buf[0] = 'A';
            socket->set(sockopt::routing_id, buf);
        }

        zmq::socket_type ZMQSenderChannel::get_socket_type()
        {
            return zmq::socket_type::router;
        }

        void ZMQSenderChannel::set_socket_options(socket_t *socket)
        {
            // Report a message a peer cannot take rather than discarding it. A ROUTER drops
            // silently by default, and returns success for the drop, so a result package
            // addressed to a receiver that has gone away, or to one whose queue is full, simply
            // ceases to exist. The receiver has already been told how many packages to expect
            // and waits out its deadline for one that was never sent, while the sender records
            // a query it answered in full. With this set the send fails instead, which the
            // dispatcher reports and the query abandons.
            socket->set(sockopt::router_mandatory, 1);

            // How far a peer may fall behind before the send above starts to fail. A receiver
            // reads packages while the sender is still computing the rest, so this has to be
            // deep enough that an ordinary difference in pace never registers, and shallow
            // enough that a peer which stops reading cannot make ZeroMQ hold an unbounded
            // amount on its behalf. See result_package_hwm.
            socket->set(sockopt::sndhwm, result_package_hwm);

            // router_mandatory makes a full queue block instead of discarding, so without this
            // a send waits on a peer that has stopped reading for as long as it stays stopped.
            socket->set(sockopt::sndtimeo, send_timeout_ms);

            // The dispatcher never takes a blocking receive, so this has no effect on the
            // serving path. It is for callers that use the blocking overload directly, which
            // would otherwise have no way back out.
            socket->set(sockopt::rcvtimeo, receive_poll_interval_ms);

            // See ZMQReceiverChannel::set_socket_options, including why this does not bound
            // the number of frames in a message.
            // NOLINTNEXTLINE(readability-redundant-parentheses): windows.h defines max
            constexpr int64_t max_message_size = (numeric_limits<int32_t>::max)();
            socket->set(sockopt::maxmsgsize, max_message_size);

            // Generous, unlike the receiver's: cutting this short would truncate an answer that
            // had in fact been computed, leaving the receiver to time out on it.
            socket->set(sockopt::linger, sender_linger_ms);
        }
    } // namespace network
} // namespace apsi
