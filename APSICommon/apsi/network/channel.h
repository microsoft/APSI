// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// STD
#include <vector>
#include <map>
#include <memory>

// APSI
#include "apsi/apsidefines.h"
//#include "apsi/psiparams.h"
#include "apsi/network/senderoperation.h"
#include "apsi/network/senderoperationresponse.h"

// SEAL
//#include "seal/publickey.h"
//#include "seal/relinkeys.h"
//#include "seal/ciphertext.h"

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
            Channel();

            /**
            * Destroy an instance of a Channel
            */
            virtual ~Channel();

            /**
            * Receive a Sender Operation.
            *
            * This call does not block if wait_for_message is false, if there
            * is no operation pending it will immediately return false.
            */
            bool receive(std::shared_ptr<apsi::network::SenderOperation>& sender_op, bool wait_for_message = false);

            /**
            * Receive Get Parameters response from Sender
            */
            void receive(apsi::network::SenderResponseGetParameters& response);

            /**
            * Receive item preprocessing response from Sender
            */
            void receive(apsi::network::SenderResponsePreprocess& response);

            /**
            * Receive Query response from Sender
            */
            void receive(apsi::network::SenderResponseQuery& response);

            /**
            Receive a ResultPackage structure
            */
            void receive(apsi::ResultPackage& pkg);

            /**
            Send a request to Get Parameters from Sender
            */
            void send_get_parameters();

            /**
            Send a response to a request to Get Parameters
            */
            void send_get_parameters_response(const std::vector<apsi::u8>& client_id, const apsi::PSIParams& params);

            /**
            Send a request to Preprocess items on Sender
            */
            void send_preprocess(const std::vector<apsi::u8>& buffer);

            /**
            * Send a response to a request to Preprocess items
            */
            void send_preprocess_response(const std::vector<apsi::u8>& client_id, const std::vector<apsi::u8>& buffer);

            /**
            * Send a request for a Query response to Sender
            */
            void send_query(
                const seal::RelinKeys& relin_keys, 
                const std::map<apsi::u64, std::vector<SeededCiphertext>>& query,
                const seed128 relin_key_seeds
            );

            /**
            Send a response to a Query request
            */
            void send_query_response(const std::vector<apsi::u8>& client_id, const size_t package_count);

            /**
            * Send a ResultPackage structure
            */
            void send(const std::vector<apsi::u8>& client_id, const apsi::ResultPackage& pkg);

            /**
            * Bind the channel to the given connection point.
            */
            void bind(const std::string& connection_point);

            /**
            * Connect the channel to the given connection point
            */
            void connect(const std::string& connection_point);

            /**
            * Disconnect from the connection point
            */
            void disconnect();

            /**
            * Get the amount of data that has been sent through the channel
            */
            u64 get_total_data_sent() const { return bytes_sent_; }

            /**
            * Get the amount of data that has been received through the channel
            */
            u64 get_total_data_received() const { return bytes_received_; }

            /**
            * Indicates whether the channel is connected to the network.
            */
            bool is_connected() const { return !end_point_.empty(); }
        };
    }
}
