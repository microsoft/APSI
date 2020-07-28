// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <mutex>

// APSI
#include "apsi/network/channel.h"

namespace apsi
{
    namespace network
    {
        /**
        Communication channel between a sender and a receiver through a stream. No data is actually
        sent, but instead saved to a stringstream that can be accessed to get the data. This allows
        downstream applications to use any custom networking solution.
        */
        class StreamChannel : public Channel
        {
        public:
            StreamChannel() = delete;

            /**
            Create an instance of StreamChannel using the given streams.
            */
            StreamChannel(std::istream &in, std::ostream &out) : in_(in), out_(out)
            {}

            /**
            Destroy an instance of a StreamChannel.
            */
            virtual ~StreamChannel() override
            {}

            /**
            Receive a SenderOperation from a receiver.
            */
            virtual bool receive(std::shared_ptr<SenderOperation> &sender_op) override;

            /**
            Receive a parameter request response from a sender.
            */
            virtual bool receive(apsi::network::SenderResponseParms &response) override;

            /**
            Receive an OPRF query response from a sender. 
            */
            virtual bool receive(apsi::network::SenderResponseOPRF &response) override;

            /**
            Receive a PSI or labeled PSI query response from sender.
            */
            virtual bool receive(apsi::network::SenderResponseQuery &response) override;

            /**
            Receive a ResultPackage.
            */
            virtual bool receive(apsi::ResultPackage &pkg) override;

            /**
            Send a parameter request to sender.
            */
            virtual void send_parms_request() override;

            /**
            Send a response to a parameter request to receiver.
            */
            virtual void send_parms_response(
                const std::vector<seal::SEAL_BYTE> &client_id, const PSIParams &params) override;

            /**
            Send an OPRF query to sender.
            */
            virtual void send_oprf_request(const std::vector<seal::SEAL_BYTE> &data) override;

            /**
            Send a response to an OPRF query to receiver.
            */
            virtual void send_oprf_response(
                const std::vector<seal::SEAL_BYTE> &client_id,
                const std::vector<seal::SEAL_BYTE> &data) override;

            /**
            Send a PSI or labeled PSI query to sender.
            */
            virtual void send_query_request(
                const std::string &relin_keys,
                const std::map<std::uint64_t,
                std::vector<std::string>> &query) override;

            /**
            Send a response to an OPRF query to receiver.
            */
            virtual void send_query_response(
                const std::vector<seal::SEAL_BYTE> &client_id, std::size_t package_count) override;

            /**
            Send a ResultPackage.
            */
            virtual void send_result_package(
                const std::vector<seal::SEAL_BYTE> &client_id, const ResultPackage &pkg) override;

        protected:
            std::istream &in_;

            std::ostream &out_;

        private:
            std::mutex receive_mutex_;

            std::mutex send_mutex_;

            /**
            Write SenderOperationType to output stream.
            */
            void write_sop_type(const SenderOperationType type);

            /**
            Read SenderOperationType from input stream.
            */
            SenderOperationType read_sop_type();

            /**
            Write a string to output stream.
            */
            void write_string(const std::string &str);

            /**
            Read a string from input stream.
            */
            void read_string(std::string &str);

            /**
            Decode a parameter request from receiver.
            */
            std::shared_ptr<SenderOperation> decode_parms_request();

            /**
            Decode an OPRF query from receiver.
            */
            std::shared_ptr<SenderOperation> decode_oprf_request();

            /**
            Decode a PSI or labeled PSI query from receiver.
            */
            std::shared_ptr<SenderOperation> decode_query_request();
        }; // class StreamChannel
    }      // namespace network
} // namespace apsi
