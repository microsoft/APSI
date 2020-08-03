// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <mutex>
#include <memory>

// APSI
#include "apsi/network/channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/result_package.h"

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
            virtual ~StreamChannel()
            {}

            /**
            Send a SenderOperation to the sender.
            */
            virtual void send(std::unique_ptr<SenderOperation> sop) override;

            /**
            Receive a SenderOperation from a receiver.
            */
            virtual std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) override;

            /**
            Send a SenderOperationResponse to the receiver.
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
            std::istream &in_;

            std::ostream &out_;

        private:
            std::mutex receive_mutex_;

            std::mutex send_mutex_;
        }; // class StreamChannel
    }      // namespace network
} // namespace apsi
