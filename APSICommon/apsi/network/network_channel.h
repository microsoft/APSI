// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

#include "apsi/network/channel.h"

namespace std
{
    class mutex;
}

namespace zmqpp
{
    class socket;
    typedef socket socket_t;
    enum class socket_type;
    class message;
    typedef message message_t;
    class context;
    typedef context context_t;
}

namespace apsi
{
    namespace network
    {
        /**
        * Communication channel between Sender and Receiver through a Network channel.
        *
        * All receives are synchrounous.
        * All sends are asynchrounous.
        */
        class NetworkChannel : public Channel
        {

        protected:
            /**
            Get socket type for this channel.
            */
            virtual zmqpp::socket_type get_socket_type() = 0;

            /**
            Add any needed options for the socket. Called just after socket creation.
            */
            virtual void set_socket_options(zmqpp::socket_t* socket) = 0;

        private:
            u64 bytes_sent_;
            u64 bytes_received_;

            std::unique_ptr<zmqpp::socket_t> socket_;
            std::string end_point_;

            std::unique_ptr<std::mutex> receive_mutex_;
            std::unique_ptr<std::mutex> send_mutex_;

            std::unique_ptr<zmqpp::context_t> context_;

            void throw_if_not_connected() const;
            void throw_if_connected() const;

            bool receive_message(zmqpp::message_t& msg, bool wait_for_message = true);
            void send_message(zmqpp::message_t& msg);

            /**
            Decode a Get Parameters message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_get_parameters(const zmqpp::message_t& msg);

            /**
            Decode a Preprocess message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_preprocess(const zmqpp::message_t& msg);

            /**
            Decode a Query message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_query(const zmqpp::message_t& msg);

            /**
            Add message type to message
            */
            void add_message_type(const SenderOperationType type, zmqpp::message_t& msg) const;

            /**
            Get message type from message.
            Message type is always part 0.
            */
            SenderOperationType get_message_type(const zmqpp::message_t& msg, const size_t part = 1) const;

            /**
            Extract client ID from a message
            */
            void extract_client_id(const zmqpp::message_t& msg, std::vector<apsi::u8>& id) const;

            /**
            Add client ID to message
            */
            void add_client_id(zmqpp::message_t& msg, const std::vector<apsi::u8>& id) const;

            /**
            Get buffer from message, located at part_start
            */
            void get_buffer(std::vector<u8>& buff, const zmqpp::message_t& msg, int part_start) const;

            /**
            Add buffer to the given message
            */
            void add_buffer(const std::vector<u8>& buff, zmqpp::message_t& msg) const;

            /**
            Get a vector of SmallModulus from message at the given part index.
            When method exits the part index will be pointing to the next part in the message, after the vector.
            */
            void get_sm_vector(std::vector<seal::SmallModulus>& smv, const zmqpp::message_t& msg, size_t& part_idx) const;

            /**
            Add a vector of SmallModulus to given message
            */
            void add_sm_vector(const std::vector<seal::SmallModulus>& smv, zmqpp::message_t& msg) const;

            /**
            Get a part from a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                get_part(T& data, const zmqpp::message_t& msg, const size_t part) const;

            /**
            Add a part to a message
            */
            template<typename T>
            typename std::enable_if<std::is_pod<T>::value, void>::type
                add_part(const T& data, zmqpp::message_t& msg) const;

            /**
            Get socket
            */
            std::unique_ptr<zmqpp::socket_t>& get_socket();
        };
    }
}
