// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <iterator>
#include <sstream>
#include <stdexcept>

// APSI
#include "apsi/fourq/random.h"
#include "apsi/log.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/util/utils.h"

// SEAL
#include "seal/randomgen.h"
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
            size_t load_from_string(string data, shared_ptr<SEALContext> context, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream, move(context));
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

        ZMQChannel::ZMQChannel() : end_point_(""), context_(make_unique<context_t>())
        {}

        ZMQChannel::~ZMQChannel()
        {
            if (is_connected()) {
                disconnect();
            }
        }

        void ZMQChannel::bind(const string &end_point)
        {
            throw_if_connected();

            try {
                end_point_ = end_point;
                get_socket()->bind(end_point);
            } catch (const zmq::error_t &) {
                APSI_LOG_ERROR("ZeroMQ failed to bind socket to endpoint " << end_point);
                throw;
            }
        }

        void ZMQChannel::connect(const string &end_point)
        {
            throw_if_connected();

            try {
                end_point_ = end_point;
                get_socket()->connect(end_point);
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
                throw runtime_error("invalid message received");
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
                return nullptr;
            }

            if (!same_serialization_version(sop_header.version)) {
                // Check that the serialization version numbers match
                APSI_LOG_ERROR(
                    "Received header indicates a serialization version number ("
                    << sop_header.version
                    << ") incompatible with the current serialization version number ("
                    << apsi_serialization_version << ")");
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
                // Unexpected operation
                APSI_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << sender_operation_type_str(sop_header.type));
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<SenderOperation> sop = nullptr;

            try {
                switch (static_cast<SenderOperationType>(sop_header.type)) {
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
                    bytes_received = load_from_string(msg[2].to_string(), move(context), *sop);
                    bytes_received_ += bytes_received;
                    break;
                default:
                    // Invalid operation
                    APSI_LOG_ERROR(
                        "Received header indicates an invalid operation type "
                        << sender_operation_type_str(sop_header.type));
                    return nullptr;
                }
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            }

            // Loaded successfully; set up ZMQSenderOperation package
            auto n_sop = make_unique<ZMQSenderOperation>();
            n_sop->client_id = move(client_id);
            n_sop->sop = move(sop);

            APSI_LOG_DEBUG(
                "Received an operation of type " << sender_operation_type_str(sop_header.type)
                                                 << " (" << bytes_received_ - old_bytes_received
                                                 << " bytes)");

            return n_sop;
        }

        unique_ptr<SenderOperation> ZMQChannel::receive_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            // Ignore the client_id
            return move(receive_network_operation(move(context), expected)->sop);
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
            n_sop_response->sop_response = move(sop_response);

            send(move(n_sop_response));
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
                throw runtime_error("invalid message received");
            }

            // First part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try {
                bytes_received_ += load_from_string(msg[0].to_string(), sop_header);
            } catch (const runtime_error &) {
                // Invalid header
                APSI_LOG_ERROR("Failed to receive a valid header");
                return nullptr;
            }

            if (!same_serialization_version(sop_header.version)) {
                // Check that the serialization version numbers match
                APSI_LOG_ERROR(
                    "Received header indicates a serialization version number "
                    << sop_header.version
                    << " incompatible with the current serialization version number "
                    << apsi_serialization_version);
                return nullptr;
            }

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type) {
                // Unexpected operation
                APSI_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << sender_operation_type_str(sop_header.type));
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<SenderOperationResponse> sop_response = nullptr;

            try {
                switch (static_cast<SenderOperationType>(sop_header.type)) {
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
                    return nullptr;
                }
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
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
                << "has label data: " << (rp->rp->label_result.size() ? "yes" : "no") << ")");

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
            n_rp->rp = move(rp);

            send(move(n_rp));
        }

        unique_ptr<ResultPackage> ZMQChannel::receive_result(shared_ptr<SEALContext> context)
        {
            throw_if_not_connected();

            bool valid_context = context && context->parameters_set();
            if (!valid_context) {
                // Cannot receive a result package without a valid SEALContext
                APSI_LOG_ERROR(
                    "Cannot receive a result package; SEALContext is missing or invalid");
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
                throw runtime_error("invalid message received");
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try {
                bytes_received = load_from_string(msg[0].to_string(), move(context), *rp);
                bytes_received_ += bytes_received;
            } catch (const invalid_argument &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            } catch (const runtime_error &ex) {
                APSI_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
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

            bool received = msg.recv(*get_socket(), static_cast<int>(receive_flags));
            if (!received && wait_for_message) {
                APSI_LOG_ERROR("ZeroMQ failed to receive a message")
                throw runtime_error("failed to receive message");
            }

            return received;
        }

        void ZMQChannel::send_message(multipart_t &msg)
        {
            lock_guard<mutex> lock(send_mutex_);

            send_result_t result = send_multipart(*get_socket(), msg, send_flags::none);
            bool sent = result.has_value();
            if (!sent) {
                throw runtime_error("failed to send message");
            }
        }

        unique_ptr<socket_t> &ZMQChannel::get_socket()
        {
            if (nullptr == socket_) {
                socket_ = make_unique<socket_t>(*context_.get(), get_socket_type());
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
            // Ensure messages are not dropped
            socket->set(sockopt::rcvhwm, 70000);

            string buf;
            buf.resize(32);
            random_bytes(
                reinterpret_cast<unsigned char *>(&buf[0]), static_cast<unsigned int>(buf.size()));
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
            // Ensure messages are not dropped
            socket->set(sockopt::sndhwm, 70000);
        }
    } // namespace network
} // namespace apsi
