// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <iterator>

// APSI
#include "apsi/network/zmq/zmq_channel.h"
#include "apsi/network/sop_header_generated.h"
#include "apsi/network/sop_generated.h"
#include "apsi/network/result_package_generated.h"

// SEAL
#include "seal/util/streambuf.h"
#include "seal/randomgen.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmq.hpp"
#include "zmq_addon.hpp"
#pragma warning(pop)

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace zmq;

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
            size_t save_to_message(const T &obj, multipart_t &msg)
            {
                stringstream ss;
                size_t size = obj.save(ss);
                msg.addstr(ss.str());
                return size;
            }

            template<>
            size_t save_to_message(const vector<seal_byte> &obj, multipart_t &msg)
            {
                msg.addmem(obj.data(), obj.size());
                return obj.size();
            }

            vector<seal_byte> get_client_id(const multipart_t &msg)
            {
                vector<seal_byte> client_id;
                size_t client_id_size = msg[0].size();
                copy_n(reinterpret_cast<const seal_byte*>(msg[0].data()), client_id_size, back_inserter(client_id));
                return client_id;
            }
        }

        ZMQChannel::ZMQChannel()
            : end_point_(""), context_(make_unique<context_t>())
        {}

        ZMQChannel::~ZMQChannel()
        {
            if (is_connected())
            {
                disconnect();
            }
        }

        void ZMQChannel::bind(const string &end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->bind(end_point);
        }

        void ZMQChannel::connect(const string &end_point)
        {
            throw_if_connected();

            end_point_ = end_point;
            get_socket()->connect(end_point);
        }

        void ZMQChannel::disconnect()
        {
            throw_if_not_connected();

            get_socket()->close();
            if (context_)
            {
                context_->shutdown();
                context_->close();
            }

            end_point_ = "";
            socket_.reset();
            context_.reset();
        }

        void ZMQChannel::throw_if_not_connected() const
        {
            if (!is_connected())
            {
                throw runtime_error("socket is not connected");
            }
        }

        void ZMQChannel::throw_if_connected() const
        {
            if (is_connected())
            {
                throw runtime_error("socket is already connected");
            }
        }

        void ZMQChannel::send(unique_ptr<SenderOperation> sop)
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

            multipart_t msg;

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        unique_ptr<ZMQSenderOperation> ZMQChannel::receive_network_operation(
            shared_ptr<SEALContext> context, bool wait_for_message, SenderOperationType expected)
        {
            throw_if_not_connected();

            multipart_t msg;
            if (!receive_message(msg, wait_for_message))
            {
                // No message yet.
                return nullptr;
            }

            // Should have client_id, SenderOperationHeader, and SenderOperation.
            if (msg.size() != 3)
            {
                throw runtime_error("invalid message received");
            }

            // First extract the client_id; this is the first part of the message
            vector<seal_byte> client_id = get_client_id(msg);

            // Second part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += load_from_string(msg[1].to_string(), sop_header);
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

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type)
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
                    case SenderOperationType::sop_parms:
                        sop = make_unique<SenderOperationParms>();
                        bytes_received_ += load_from_string(msg[2].to_string(), *sop);
                        break;
                    case SenderOperationType::sop_oprf:
                        sop = make_unique<SenderOperationOPRF>();
                        bytes_received_ += load_from_string(msg[2].to_string(), *sop);
                        break;
                    case SenderOperationType::sop_query:
                        sop = make_unique<SenderOperationQuery>();
                        bytes_received_ += load_from_string(msg[2].to_string(), move(context), *sop);
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

            // Loaded successfully; set up ZMQSenderOperation package
            auto n_sop = make_unique<ZMQSenderOperation>();
            n_sop->client_id = move(client_id);
            n_sop->sop = move(sop);

            return n_sop;
        }

        unique_ptr<ZMQSenderOperation> ZMQChannel::receive_network_operation(
            shared_ptr<SEALContext> context, SenderOperationType expected)
        {
            return receive_network_operation(move(context), false, expected);
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
            if (!sop_response)
            {
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            SenderOperationHeader sop_header;
            sop_header.type = sop_response->sop_response->type();

            size_t bytes_sent = 0;

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(sop_response->client_id, msg);

            bytes_sent += save_to_message(sop_header, msg);
            bytes_sent += save_to_message(*sop_response->sop_response, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        void ZMQChannel::send(unique_ptr<SenderOperationResponse> sop_response)
        {
            // Leave the client_id empty
            auto n_sop_response = make_unique<ZMQSenderOperationResponse>();
            n_sop_response->sop_response = move(sop_response);

            send(move(n_sop_response));
        }

        unique_ptr<SenderOperationResponse> ZMQChannel::receive_response(SenderOperationType expected)
        {
            throw_if_not_connected();

            multipart_t msg;
            if (!receive_message(msg))
            {
                // No message yet.
                return nullptr;
            }

            // Should have SenderOperationHeader and SenderOperationResponse.
            if (msg.size() != 2)
            {
                throw runtime_error("invalid message received");
            }

            // First part is the SenderOperationHeader
            SenderOperationHeader sop_header;
            try
            {
                bytes_received_ += load_from_string(msg[0].to_string(), sop_header);
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

            if (expected != SenderOperationType::sop_unknown && expected != sop_header.type)
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
                    case SenderOperationType::sop_parms:
                        sop_response = make_unique<SenderOperationResponseParms>();
                        bytes_received_ += load_from_string(msg[1].to_string(), *sop_response);
                        break;
                    case SenderOperationType::sop_oprf:
                        sop_response = make_unique<SenderOperationResponseOPRF>();
                        bytes_received_ += load_from_string(msg[1].to_string(), *sop_response);
                        break;
                    case SenderOperationType::sop_query:
                        sop_response = make_unique<SenderOperationResponseQuery>();
                        bytes_received_ += load_from_string(msg[1].to_string(), *sop_response);
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

        void ZMQChannel::send(unique_ptr<ZMQResultPackage> rp)
        {
            throw_if_not_connected();

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(rp->client_id, msg);

            size_t bytes_sent = save_to_message(*rp->rp, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;
        }

        void ZMQChannel::send(unique_ptr<ResultPackage> rp)
        {
            // Leave the client_id empty
            auto n_rp = make_unique<ZMQResultPackage>();
            n_rp->rp = move(rp);

            send(move(n_rp));
        }

        unique_ptr<ResultPackage> ZMQChannel::receive_result_package(shared_ptr<SEALContext> context)
        {
            throw_if_not_connected();

            multipart_t msg;
            if (!receive_message(msg))
            {
                // No message yet.
                return nullptr;
            }

            // Should have only one part: ResultPackage.
            if (msg.size() != 1)
            {
                throw runtime_error("invalid message received");
            }

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try
            {
                bytes_received_ += load_from_string(msg[0].to_string(), move(context), *rp);
            }
            catch (const runtime_error &ex)
            {
                // Invalid result package data
                return nullptr;
            }

            // Loaded successfully
            return rp;
        }

        bool ZMQChannel::receive_message(multipart_t &msg, bool wait_for_message)
        {
            lock_guard<mutex> lock(receive_mutex_);

            msg.clear();
            recv_flags receive_flags = wait_for_message? recv_flags::none : recv_flags::dontwait;
            bool received = msg.recv(*get_socket(), static_cast<int>(receive_flags));
            // recv_result_t result = recv_multipart(*get_socket(), move(msg), receive_flags);
            // bool received = result.has_value();
            if (!received && wait_for_message)
            {
                throw runtime_error("failed to receive message");
            }

            return received;
        }

        void ZMQChannel::send_message(multipart_t &msg)
        {
            lock_guard<mutex> lock(send_mutex_);

            send_result_t result = send_multipart(*get_socket(), msg, send_flags::none);
            bool sent = result.has_value();
            if (!sent)
            {
                throw runtime_error("failed to send message");
            }
        }

        unique_ptr<socket_t> &ZMQChannel::get_socket()
        {
            if (nullptr == socket_)
            {
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

            auto factory = seal::UniformRandomGeneratorFactory::DefaultFactory();
            auto prng = factory->create();
            string buf;
            buf.resize(32);
            prng->generate(buf.size(), reinterpret_cast<seal_byte*>(buf.data()));
            // make sure first byte is _not_ zero, as that has a special meaning for ZeroMQ
            *buf.data() = 'A';
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
