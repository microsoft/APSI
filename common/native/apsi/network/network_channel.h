// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
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
            virtual void send(std::unique_ptr<SenderOperation> sop) override;

            /**
            Receive a SenderOperation from a receiver.
            */
            virtual std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) override;

            /**
            Receive a SenderOperation from a receiver. This call does not block if wait_for_message is false. If there
            is no operation pending, it will immediately return nullptr.
            */
            std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context, bool wait_for_message,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN);

            /**
            Send a SenderOperationResponse to a receiver.
            */
            virtual void send(std::unique_ptr<SenderOperationResponse> sop_response) override;

            /**
            Receive a SenderOperationResponse from a sender.
            */
            virtual std::unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) override;

            /**
            Send a ResultPackage to a receiver.
            */
            virtual void send(const ResultPackage &rp) override;

            /**
            Receive a ResultPackage from a sender.
            */
            virtual std::unique_ptr<ResultPackage> receive_result_package(
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
    }      // namespace network
} // namespace apsi
