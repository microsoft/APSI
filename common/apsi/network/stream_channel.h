// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <memory>
#include <mutex>

// APSI
#include "apsi/network/channel.h"
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"

namespace apsi {
    namespace network {
        /**
        StreamChannel is a communication channel between a sender and a receiver through a C++
        stream. No data is actually sent, but instead saved to a std::stringstream that can be
        accessed to get the data. This allows downstream applications to use any custom networking
        solution.
        */
        class StreamChannel : public Channel {
        public:
            StreamChannel() = delete;

            /**
            Create an instance of a StreamChannel using the given input and output streams.
            */
            StreamChannel(std::istream &in, std::ostream &out) : in_(in), out_(out)
            {}

            /**
            Create an instance of a StreamChannel using the given stream for input and output.
            */
            StreamChannel(std::iostream &stream) : StreamChannel(stream, stream)
            {}

            /**
            Destroy an instance of a StreamChannel.
            */
            ~StreamChannel()
            {}

            /**
            Send a SenderOperation from a receiver to a sender. These operations represent either a
            parameter request, an OPRF request, or a query request. The function throws an exception
            on failure.
            */
            void send(std::unique_ptr<SenderOperation> sop) override;

            /**
            Receive a SenderOperation from a receiver. Operations of type sop_query and sop_unknown
            require a valid seal::SEALContext to be provided. For operations of type sop_parms and
            sop_oprf the context can be set as nullptr. The function returns nullptr on failure.
            */
            std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::sop_unknown) override;

            /**
            Send a SenderOperationResponse from a sender to a receiver. These operations represent a
            response to either a parameter request, an OPRF request, or a query request. The
            function throws and exception on failure.
            */
            void send(std::unique_ptr<SenderOperationResponse> sop_response) override;

            /**
            Receive a SenderOperationResponse from a sender. The function returns nullptr on
            failure.
            */
            std::unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected = SenderOperationType::sop_unknown) override;

            /**
            Send a ResultPackage to a receiver. The function throws and exception on failure.
            */
            void send(std::unique_ptr<ResultPackage> rp) override;

            /**
            Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
            function returns nullptr on failure.
            */
            std::unique_ptr<ResultPackage> receive_result(
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
