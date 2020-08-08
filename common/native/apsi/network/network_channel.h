// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <utility>
#include <mutex>
#include <memory>
#include <type_traits>

// APSI
#include "apsi/network/channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/result_package.h"

namespace zmqpp
{
    class socket;
    typedef socket socket_t;
    enum class socket_type;
    class message;
    typedef message message_t;
    class context;
    typedef context context_t;
} // namespace zmqpp

namespace apsi
{
    namespace network
    {
        /**
        Encapsulates a SenderOperation and a client identifier used internally by ZeroMQ.
        */
        struct NetworkSenderOperation
        {
            std::unique_ptr<SenderOperation> sop;

            std::vector<seal::SEAL_BYTE> client_id;
        };

        /**
        Encapsulates a SenderOperationResponse and a client identifier used internally by ZeroMQ.
        */
        struct NetworkSenderOperationResponse
        {
            std::unique_ptr<SenderOperationResponse> sop_response;

            std::vector<seal::SEAL_BYTE> client_id;
        };

        /**
        Encapsulates a ResultPackage and a client identifier used internally by ZeroMQ.
        */
        struct NetworkResultPackage
        {
            std::unique_ptr<ResultPackage> rp;

            std::vector<seal::SEAL_BYTE> client_id;
        };

        /**
        Communication channel between Sender and Receiver through a Network channel. All receives are synchronous,
        except for receiving a SenderOperation. All sends are asynchrounous.
        */
        class NetworkChannel : public Channel
        {
        public:
            NetworkChannel();

            virtual ~NetworkChannel();

            /**
            Bind the channel to the given connection point.
            */
            void bind(const std::string &connection_point);

            /**
            Connect the channel to the given connection point.
            */
            void connect(const std::string &connection_point);

            /**
            Disconnect from the connection point.
            */
            void disconnect();

            /**
            Returns whether the channel is in a connected state.
            */
            bool is_connected() const
            {
                return !end_point_.empty();
            }

            /**
            Send a SenderOperation to a sender.
            */
            void send(std::unique_ptr<SenderOperation> sop) override;

            /**
            Receive a SenderOperation from a receiver. This call does not block if wait_for_message is false. If there
            is no operation pending, it will immediately return nullptr.
            */
            virtual std::unique_ptr<NetworkSenderOperation> receive_network_operation(
                std::shared_ptr<seal::SEALContext> context, bool wait_for_message,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN);

            /**
            Receive a NetworkSenderOperation from a receiver.
            */
            virtual std::unique_ptr<NetworkSenderOperation> receive_network_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN);

            /**
            Receive a SenderOperation from a receiver.
            */
            std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) override;

            /**
            Send a NetworkSenderOperationResponse to a receiver.
            */
            virtual void send(std::unique_ptr<NetworkSenderOperationResponse> sop_response);

            /**
            Send a SenderOperationResponse to a receiver.
            */
            void send(std::unique_ptr<SenderOperationResponse> sop_response) override;

            /**
            Receive a SenderOperationResponse from a sender.
            */
            std::unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) override;

            /**
            Send a NetworkResultPackage to a receiver.
            */
            virtual void send(std::unique_ptr<NetworkResultPackage> rp);

            /**
            Send a ResultPackage to a receiver.
            */
            void send(std::unique_ptr<ResultPackage> rp) override;

            /**
            Receive a ResultPackage from a sender.
            */
            std::unique_ptr<ResultPackage> receive_result_package(
                std::shared_ptr<seal::SEALContext> context) override;

        protected:
            /**
            Get socket type for this channel.
            */
            virtual zmqpp::socket_type get_socket_type() = 0;

            /**
            Add any needed options for the socket. Called just after socket creation.
            */
            virtual void set_socket_options(zmqpp::socket_t *socket) = 0;

        private:
            std::unique_ptr<zmqpp::socket_t> socket_;

            std::string end_point_;

            std::mutex receive_mutex_;

            std::mutex send_mutex_;

            std::unique_ptr<zmqpp::context_t> context_;

            std::unique_ptr<zmqpp::socket_t> &get_socket();

            void throw_if_not_connected() const;

            void throw_if_connected() const;

            bool receive_message(zmqpp::message_t &msg, bool wait_for_message = true);

            void send_message(zmqpp::message_t &msg);
        }; // class NetworkChannel

        /**
        Represents a network channel for a sender.
        */
        class SenderChannel : public NetworkChannel
        {
        public:
            SenderChannel() = default;

            ~SenderChannel()
            {
            }

        protected:
            /**
            The only difference from a receiver is the socket type.
            */
            zmqpp::socket_type get_socket_type() override;

            /**
            The sender needs to set a couple of socket options to ensure messages are not dropped.
            */
            void set_socket_options(zmqpp::socket_t *socket) override;
        };

        /**
        Represents a network channel for a receiver.
        */
        class ReceiverChannel : public NetworkChannel
        {
        public:
            ReceiverChannel() = default;

            ~ReceiverChannel()
            {
            }

        protected:
            /**
            The only difference from a sender is the socket type.
            */
            zmqpp::socket_type get_socket_type() override;

            /**
            The receiver needs to set a couple of socket options to ensure messages are not dropped.
            */
            void set_socket_options(zmqpp::socket_t *socket) override;
        };
    }      // namespace network
} // namespace apsi
