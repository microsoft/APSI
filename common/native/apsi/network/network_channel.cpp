// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <stdexcept>
#include <sstream>

// APSI
#include "apsi/network/network_channel.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/result_package_generated.h"

// SEAL
#include "seal/util/streambuf.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace zmqpp;

namespace apsi
{
    namespace network
    {
        namespace
        {
            template<typename T>
            size_t load_from_string(string data, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()), static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream);
            }

            template<typename T>
            size_t load_from_string(string data, shared_ptr<SEALContext> context, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()), static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream, move(context));
            }

            template<typename T>
            size_t save_to_message(const T &obj, message_t &msg)
            {
                stringstream ss;
                size_t size = obj.save(ss);
                msg.add(ss.str());
                return size;
            }

            template<>
            size_t save_to_message(const vector<SEAL_BYTE> &obj, message_t &msg)
            {
                msg.add_raw(obj.data(), obj.size());
                return obj.size();
            }

            vector<SEAL_BYTE> get_client_id(const message_t &msg)
            {
                vector<SEAL_BYTE> client_id;
                size_t client_id_size = msg.size(0);
                client_id.resize(client_id_size);
                memcpy(client_id.data(), msg.raw_data(0), client_id_size);
                return client_id;
            }
        }

        NetworkChannel::NetworkChannel()
            : end_point_(""), context_(make_unique<context_t>())
        {}

        NetworkChannel::~NetworkChannel()
        {
            if (is_connected())
            {
                disconnect();
            }
        }

        void NetworkChannel::bind(const string &end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->bind(end_point);
        }

        void NetworkChannel::connect(const string &end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->connect(end_point);
        }

        void NetworkChannel::disconnect()
        {
            throw_if_not_connected();

            get_socket()->close();
            if (context_)
            {
                context_->terminate();
            }

            end_point_ = "";
            socket_.reset();
            context_.reset();
        }

        void NetworkChannel::throw_if_not_connected() const
        {
            if (!is_connected())
            {
                throw runtime_error("socket is not connected");
            }
        }

        void NetworkChannel::throw_if_connected() const
        {
            if (is_connected())
            {
                throw runtime_error("socket is already connected");
            }
        }

        void NetworkChannel::send(unique_ptr<SenderOperation> sop)
        {
            throw_if_not_connected();

            // Need to have the SenderOperation package
            if (!sop)
            {
                throw invalid_argument("operation data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop->type();

            size_t bytes_sent = 0;

            message_t msg;

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        unique_ptr<NetworkSenderOperation> NetworkChannel::receive_network_operation(
            shared_ptr<SEALContext> context, bool wait_for_message, SenderOperationType expected)
        {
            throw_if_not_connected();

            message_t msg;
            if (!receive_message(msg, wait_for_message))
            {
                // No message yet.
                return nullptr;
            }

            // Should have client_id, SenderOperationHeader, and SenderOperation.
            if (msg.parts() != 3)
            {
                throw runtime_error("invalid message received");
            }

            // First extract the client_id; this is the first part of the message
            vector<SEAL_BYTE> client_id = get_client_id(msg);

            // Second part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += load_from_string(msg.get(1), sop_header);
            }
            catch (const runtime_error &ex)
            {
                // Invalid header
                return nullptr;
            }

            if (!same_version(sop_header.version))
            {
                // Check that the version numbers match exactly
                return nullptr;
            }

            if (expected != SenderOperationType::SOP_UNKNOWN && expected != sop_header.type)
            {
                // Unexpected operation
                return nullptr;
            }

            // Return value
            unique_ptr<SenderOperation> sop = nullptr;

            try
            {
                switch (static_cast<SenderOperationType>(sop_header.type))
                {
                    case SenderOperationType::SOP_PARMS:
                        sop = make_unique<SenderOperationParms>();
                        bytes_received_ += load_from_string(msg.get(2), *sop);
                        break;
                    case SenderOperationType::SOP_OPRF:
                        sop = make_unique<SenderOperationOPRF>();
                        bytes_received_ += load_from_string(msg.get(2), *sop);
                        break;
                    case SenderOperationType::SOP_QUERY:
                        sop = make_unique<SenderOperationQuery>();
                        bytes_received_ += load_from_string(msg.get(2), move(context), *sop);
                        break;
                    default:
                        // Invalid operation
                        return nullptr;
                }
            }
            catch (const invalid_argument &ex)
            {
                // Invalid SEALContext
                return nullptr;
            }
            catch (const runtime_error &ex)
            {
                // Invalid operation data
                return nullptr;
            }

            // Loaded successfully; set up NetworkSenderOperation package
            auto n_sop = make_unique<NetworkSenderOperation>();
            n_sop->client_id = move(client_id);
            n_sop->sop = move(sop);

            return n_sop;
        }

        unique_ptr<NetworkSenderOperation> NetworkChannel::receive_network_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            return receive_network_operation(move(context), /* wait_for_message */ false, expected);
        }

        unique_ptr<SenderOperation> NetworkChannel::receive_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            // Ignore the client_id
            return move(receive_network_operation(move(context), expected)->sop);
        }

        void NetworkChannel::send(unique_ptr<NetworkSenderOperationResponse> sop_response)
        {
            throw_if_not_connected();

            // Need to have the SenderOperationResponse package
            if (!sop_response)
            {
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop_response->sop_response->type();

            size_t bytes_sent = 0;

            message_t msg;

            // Add the client_id as the first part
            save_to_message(sop_response->client_id, msg);

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop_response->sop_response, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        void NetworkChannel::send(unique_ptr<SenderOperationResponse> sop_response)
        {
            // Leave the client_id empty
            auto n_sop_response = make_unique<NetworkSenderOperationResponse>();
            n_sop_response->sop_response = move(sop_response);

            send(move(n_sop_response));
        }

        unique_ptr<SenderOperationResponse> NetworkChannel::receive_response(SenderOperationType expected)
        {
            throw_if_not_connected();

            message_t msg;
            if (!receive_message(msg))
            {
                // No message yet.
                return nullptr;
            }

            // Should have SenderOperationHeader and SenderOperationResponse.
            if (msg.parts() != 2)
            {
                throw runtime_error("invalid message received");
            }

            // First part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += load_from_string(msg.get(0), sop_header);
            }
            catch (const runtime_error &ex)
            {
                // Invalid header
                return nullptr;
            }

            if (!same_version(sop_header.version))
            {
                // Check that the version numbers match exactly
                return nullptr;
            }

            if (expected != SenderOperationType::SOP_UNKNOWN && expected != sop_header.type)
            {
                // Unexpected operation
                return nullptr;
            }

            // Return value
            unique_ptr<SenderOperationResponse> sop_response = nullptr;

            try
            {
                switch (static_cast<SenderOperationType>(sop_header.type))
                {
                    case SenderOperationType::SOP_PARMS:
                        sop_response = make_unique<SenderOperationResponseParms>();
                        bytes_received_ += load_from_string(msg.get(1), *sop_response);
                        break;
                    case SenderOperationType::SOP_OPRF:
                        sop_response = make_unique<SenderOperationResponseOPRF>();
                        bytes_received_ += load_from_string(msg.get(1), *sop_response);
                        break;
                    case SenderOperationType::SOP_QUERY:
                        sop_response = make_unique<SenderOperationResponseQuery>();
                        bytes_received_ += load_from_string(msg.get(1), *sop_response);
                        break;
                    default:
                        // Invalid operation
                        return nullptr;
                }
            }
            catch (const runtime_error &ex)
            {
                // Invalid operation data
                return nullptr;
            }

            // Loaded successfully
            return sop_response;
        }

        void NetworkChannel::send(unique_ptr<NetworkResultPackage> rp)
        {
            throw_if_not_connected();

            message_t msg;

            // Add the client_id as the first part
            save_to_message(rp->client_id, msg);

            size_t bytes_sent = save_to_message(*rp->rp, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        void NetworkChannel::send(unique_ptr<ResultPackage> rp)
        {
            // Leave the client_id empty
            auto n_rp = make_unique<NetworkResultPackage>();
            n_rp->rp = move(rp);

            send(move(n_rp));
        }

        unique_ptr<ResultPackage> NetworkChannel::receive_result_package(shared_ptr<SEALContext> context)
        {
            throw_if_not_connected();

            message_t msg;
            if (!receive_message(msg))
            {
                // No message yet.
                return nullptr;
            }

            // Should have only one part: ResultPackage.
            if (msg.parts() != 1)
            {
                throw runtime_error("invalid message received");
            }

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try
            {
                bytes_received_ += load_from_string(msg.get(0), move(context), *rp);
            }
            catch (const runtime_error &ex)
            {
                // Invalid result package data
                return nullptr;
            }

            // Loaded successfully
            return rp;
        }

        bool NetworkChannel::receive_message(message_t &msg, bool wait_for_message)
        {
            lock_guard<mutex> lock(receive_mutex_);

            bool received = get_socket()->receive(msg, !wait_for_message);
            if (!received && wait_for_message)
            {
                throw runtime_error("failed to receive message");
            }

            return received;
        }

        void NetworkChannel::send_message(message_t &msg)
        {
            lock_guard<mutex> lock(send_mutex_);

            bool sent = get_socket()->send(msg);
            if (!sent)
            {
                throw runtime_error("failed to send message");
            }
        }

        unique_ptr<socket_t> &NetworkChannel::get_socket()
        {
            if (nullptr == socket_)
            {
                socket_ = make_unique<socket_t>(*context_.get(), get_socket_type());
                set_socket_options(socket_.get());
            }

            return socket_;
        }

        socket_type ReceiverChannel::get_socket_type()
        {
            return socket_type::dealer;
        }

        void ReceiverChannel::set_socket_options(socket_t *socket)
        {
            // Ensure messages are not dropped
            socket->set(socket_option::receive_high_water_mark, 70000);
        }

        socket_type SenderChannel::get_socket_type()
        {
            return socket_type::router;
        }

        void SenderChannel::set_socket_options(socket_t *socket)
        {
            // Ensure messages are not dropped
            socket->set(socket_option::send_high_water_mark, 70000);
        }
    } // namespace network
} // namespace apsi
