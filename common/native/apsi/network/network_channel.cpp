// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <utility>
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
            sop_header.client_id = sop->client_id;

            size_t bytes_sent = 0;

            message_t msg;
            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        unique_ptr<SenderOperation> NetworkChannel::receive_operation(
            shared_ptr<SEALContext> context, bool wait_for_message, SenderOperationType expected)
        {
            throw_if_not_connected();

            message_t msg;
            if (!receive_message(msg, wait_for_message))
            {
                // No message yet.
                return nullptr;
            }

            // Should have SenderOperationHeader and SenderOperation.
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
                        bytes_received_ += load_from_string(msg.get(1), *sop);
                        break;
                    case SenderOperationType::SOP_OPRF:
                        sop = make_unique<SenderOperationOPRF>();
                        bytes_received_ += load_from_string(msg.get(1), *sop);
                        break;
                    case SenderOperationType::SOP_QUERY:
                        sop = make_unique<SenderOperationQuery>();
                        bytes_received_ += load_from_string(msg.get(1), move(context), *sop);
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

            // Check whether the client IDs match
            if (sop_header.client_id != sop->client_id)
            {
                // Client ID mismatch
                return nullptr;
            }

            // Loaded successfully
            return sop;
        }

        unique_ptr<SenderOperation> NetworkChannel::receive_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            return receive_operation(move(context), /* wait_for_message */ false, expected);
        }

        void NetworkChannel::send(unique_ptr<SenderOperationResponse> sop_response)
        {
            throw_if_not_connected();

            // Need to have the SenderOperationResponse package
            if (!sop_response)
            {
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop_response->type();
            sop_header.client_id = sop_response->client_id;

            size_t bytes_sent = 0;

            message_t msg;
            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop_response, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
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

            // Check whether the client IDs match
            if (sop_header.client_id != sop_response->client_id)
            {
                // Client ID mismatch
                return nullptr;
            }

            // Loaded successfully
            return sop_response;
        }

        void NetworkChannel::send(const ResultPackage &rp)
        {
            throw_if_not_connected();

            message_t msg;
            size_t bytes_sent = save_to_message(rp, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
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
    } // namespace network
} // namespace apsi
