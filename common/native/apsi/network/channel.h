// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <cstdint>
#include <cstddef>
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
        Communication channel between a sender and a receiver.
        */
        class Channel
        {
        public:
            /**
            Create an instance of a Channel.
            */
            Channel() : bytes_sent_(0), bytes_received_(0)
            {}

            /**
            Destroy an instance of a Channel.
            */
            virtual ~Channel()
            {}

            /**
            Receive a SenderOperation from a receiver.
            */
            virtual bool receive(std::shared_ptr<SenderOperation> &sender_op) = 0;

            /**
            Receive a parameter request response from a sender.
            */
            virtual bool receive(apsi::network::SenderResponseParms &response) = 0;

            /**
            Receive an OPRF query response from a sender. 
            */
            virtual bool receive(apsi::network::SenderResponseOPRF &response) = 0;

            /**
            Receive a PSI or labeled PSI query response from sender.
            */
            virtual bool receive(apsi::network::SenderResponseQuery &response) = 0;

            /**
            Receive a ResultPackage.
            */
            virtual bool receive(apsi::ResultPackage &pkg) = 0;

            /**
            Send a parameter request to sender.
            */
            virtual void send_parms_request() = 0;

            /**
            Send a response to a parameter request to receiver.
            */
            virtual void send_parms_response(
                const std::vector<seal::SEAL_BYTE> &client_id, const PSIParams &params) = 0;

            /**
            Send an OPRF query to sender.
            */
            virtual void send_oprf_request(const std::vector<seal::SEAL_BYTE> &data) = 0;

            /**
            Send a response to an OPRF query to receiver.
            */
            virtual void send_oprf_response(
                const std::vector<seal::SEAL_BYTE> &client_id, const std::vector<seal::SEAL_BYTE> &data) = 0;

            /**
            Send a PSI or labeled PSI query to sender.
            */
            virtual void send_query_request(
                const std::string &relin_keys, const std::map<std::uint64_t, std::vector<std::string>> &data) = 0;

            /**
            Send a response to an OPRF query to receiver.
            */
            virtual void send_query_response(
                const std::vector<seal::SEAL_BYTE> &client_id, std::size_t package_count) = 0;

            /**
            Send a ResultPackage.
            */
            virtual void send_result_package(
                const std::vector<seal::SEAL_BYTE> &client_id, const ResultPackage &pkg) = 0;

            /**
            Get the amount of data that has been sent through the channel
            */
            std::uint64_t bytes_sent() const
            {
                return bytes_sent_;
            }

            /**
            Get the amount of data that has been received through the channel
            */
            std::uint64_t bytes_received() const
            {
                return bytes_received_;
            }

        protected:
            std::uint64_t bytes_sent_;

            std::uint64_t bytes_received_;
        }; // class Channel
    }      // namespace network
} // namespace apsi
