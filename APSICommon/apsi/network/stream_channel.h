// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <istream>
#include <ostream>
#include <mutex>

// APSI
#include "apsi/network/channel.h"


namespace apsi
{
    namespace network
    {
        /**
        * Communication channel between Sender and Receiver through a Stream.
        *
        * No data is actually sent, it is all saved to a stringstream that can be accessed to get the data.
        */
        class StreamChannel : public Channel
        {
        public:
            StreamChannel() = delete;

            /**
            * Create an instance of StreamChannel using the given streams
            */
            StreamChannel(std::istream& istream, std::ostream& ostream);

            /**
            * Destroy an instance of StreamChannel
            */
            virtual ~StreamChannel();

            /**
            * Receive a Sender Operation.
            */
            virtual bool receive(std::shared_ptr<apsi::network::SenderOperation>& sender_op);

            /**
            * Receive Get Parameters response from Sender
            */
            virtual void receive(apsi::network::SenderResponseGetParameters& response);

            /**
            * Receive item preprocessing response from Sender
            */
            virtual void receive(apsi::network::SenderResponsePreprocess& response);

            /**
            * Receive Query response from Sender
            */
            virtual void receive(apsi::network::SenderResponseQuery& response);

            /**
            Receive a ResultPackage structure
            */
            virtual void receive(apsi::ResultPackage& pkg);

            /**
            Send a request to Get Parameters from Sender
            */
            virtual void send_get_parameters();

            /**
            Send a response to a request to Get Parameters
            */
            virtual void send_get_parameters_response(const std::vector<apsi::u8>& client_id, const apsi::PSIParams& params);

            /**
            Send a request to Preprocess items on Sender
            */
            virtual void send_preprocess(const std::vector<apsi::u8>& buffer);

            /**
            * Send a response to a request to Preprocess items
            */
            virtual void send_preprocess_response(const std::vector<apsi::u8>& client_id, const std::vector<apsi::u8>& buffer);

            /**
            * Send a request for a Query response to Sender
            */
            virtual void send_query(
                const std::string& relin_keys,
                const std::map<apsi::u64, std::vector<std::string>>& query);

            /**
            Send a response to a Query request
            */
            virtual void send_query_response(const std::vector<apsi::u8>& client_id, const size_t package_count);

            /**
            * Send a ResultPackage structure
            */
            virtual void send(const std::vector<apsi::u8>& client_id, const apsi::ResultPackage& pkg);

        protected:
            std::istream& istream_;
            std::ostream& ostream_;

        private:
            std::unique_ptr<std::mutex> receive_mutex_;
            std::unique_ptr<std::mutex> send_mutex_;

            /**
            Write operation type
            */
            void write_operation_type(const SenderOperationType type);

            /**
            Read operation type
            */
            SenderOperationType read_operation_type();

            /**
            Write a string
            */
            void write_string(const std::string& str);

            /**
            Read a string
            */
            void read_string(std::string& str);

            /**
            Decode a Get Parameters message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_get_parameters();

            /**
            Decode a Preprocess message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_preprocess();

            /**
            Decode a Query message
            */
            std::shared_ptr<apsi::network::SenderOperation>
                decode_query();
        };
    }
}
