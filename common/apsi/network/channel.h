// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

// APSI
#include "apsi/network/result_package.h"
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"

// SEAL
#include "seal/util/defines.h"

namespace apsi {
    namespace network {
        /**
        Channel is an interfacate to implement a communication channel between a sender and a
        receiver. It keeps track of the number of bytes sent and received.
        */
        class Channel {
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
            Send a SenderOperation from a receiver to a sender. These operations represent either a
            parameter request, an OPRF request, or a query request. The function throws an exception
            on failure.
            */
            virtual void send(std::unique_ptr<SenderOperation> sop) = 0;

            /**
            Receive a SenderOperation from a receiver. Operations of type sop_query and sop_unknown
            require a valid seal::SEALContext to be provided. For operations of type sop_parms and
            sop_oprf the context can be set as nullptr. The function returns nullptr on failure.
            */
            virtual std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::sop_unknown) = 0;

            /**
            Send a SenderOperationResponse from a sender to a receiver. These operations represent a
            response to either a parameter request, an OPRF request, or a query request. The
            function throws and exception on failure.
            */
            virtual void send(std::unique_ptr<SenderOperationResponse> sop_response) = 0;

            /**
            Receive a SenderOperationResponse from a sender. The function returns nullptr on
            failure.
            */
            virtual std::unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected = SenderOperationType::sop_unknown) = 0;

            /**
            Send a ResultPackage to a receiver. The function throws and exception on failure.
            */
            virtual void send(std::unique_ptr<ResultPackage> rp) = 0;

            /**
            Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
            function returns nullptr on failure.
            */
            virtual std::unique_ptr<ResultPackage> receive_result(
                std::shared_ptr<seal::SEALContext> context) = 0;

            /**
            Returns the number of bytes sent on the channel.
            */
            std::uint64_t bytes_sent() const
            {
                return bytes_sent_;
            }

            /**
            Returns the number of bytes received on the channel.
            */
            std::uint64_t bytes_received() const
            {
                return bytes_received_;
            }

        protected:
            std::atomic<std::uint64_t> bytes_sent_;

            std::atomic<std::uint64_t> bytes_received_;
        }; // class Channel
    }      // namespace network
} // namespace apsi
