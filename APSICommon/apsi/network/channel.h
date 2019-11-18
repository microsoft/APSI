// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <map>
#include <memory>

// APSI
#include "apsi/network/senderoperation.h"
#include "apsi/network/senderoperationresponse.h"


namespace apsi
{
    struct ResultPackage;

    namespace network
    {
        /**
        * Communication channel between Sender and Receiver.
        */
        class Channel
        {
        public:
            /**
            * Create an instance of a Channel
            */
            Channel()
                : bytes_sent_(0),
                  bytes_received_(0)
            {
            }

            /**
            * Destroy an instance of a Channel
            */
            virtual ~Channel()
            {
            }

            /**
            * Receive a Sender Operation.
            */
            virtual bool receive(std::shared_ptr<apsi::network::SenderOperation>& sender_op) = 0;

            /**
            * Receive Get Parameters response from Sender
            */
            virtual void receive(apsi::network::SenderResponseGetParameters& response) = 0;

            /**
            * Receive item preprocessing response from Sender
            */
            virtual void receive(apsi::network::SenderResponsePreprocess& response) = 0;

            /**
            * Receive Query response from Sender
            */
            virtual void receive(apsi::network::SenderResponseQuery& response) = 0;

            /**
            Receive a ResultPackage structure
            */
            virtual void receive(apsi::ResultPackage& pkg) = 0;

            /**
            Send a request to Get Parameters from Sender
            */
            virtual void send_get_parameters() = 0;

            /**
            Send a response to a request to Get Parameters
            */
            virtual void send_get_parameters_response(const std::vector<apsi::u8>& client_id, const apsi::PSIParams& params) = 0;

            /**
            Send a request to Preprocess items on Sender
            */
            virtual void send_preprocess(const std::vector<apsi::u8>& buffer) = 0;

            /**
            * Send a response to a request to Preprocess items
            */
            virtual void send_preprocess_response(const std::vector<apsi::u8>& client_id, const std::vector<apsi::u8>& buffer) = 0;

            /**
            * Send a request for a Query response to Sender
            */
            virtual void send_query(
                const std::string& relin_keys, 
                const std::map<apsi::u64, std::vector<std::string>>& query) = 0;

            /**
            Send a response to a Query request
            */
            virtual void send_query_response(const std::vector<apsi::u8>& client_id, const size_t package_count) = 0;

            /**
            * Send a ResultPackage structure
            */
            virtual void send(const std::vector<apsi::u8>& client_id, const apsi::ResultPackage& pkg) = 0;

            /**
            * Get the amount of data that has been sent through the channel
            */
            u64 get_total_data_sent() const { return bytes_sent_; }

            /**
            * Get the amount of data that has been received through the channel
            */
            u64 get_total_data_received() const { return bytes_received_; }

        protected:
            u64 bytes_sent_;
            u64 bytes_received_;
        };
    }
}
