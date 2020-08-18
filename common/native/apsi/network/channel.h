// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <cstdint>
#include <cstddef>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sender_operation_response.h"
#include "apsi/network/result_package.h"

// SEAL
#include "seal/util/defines.h"

namespace apsi
{
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
            Send a SenderOperation to a sender.
            */
            virtual void send(std::unique_ptr<SenderOperation> sop) = 0;

            /**
            Receive a SenderOperation from a receiver.
            */
            virtual std::unique_ptr<SenderOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) = 0;

            /**
            Send a SenderOperationResponse to a receiver.
            */
            virtual void send(std::unique_ptr<SenderOperationResponse> sop_response) = 0;

            /**
            Receive a SenderOperationResponse from a sender.
            */
            virtual std::unique_ptr<SenderOperationResponse> receive_response(
                SenderOperationType expected = SenderOperationType::SOP_UNKNOWN) = 0;

            /**
            Send a ResultPackage to a receiver.
            */
            virtual void send(std::unique_ptr<ResultPackage> rp) = 0;

            /**
            Receive a ResultPackage from a sender.
            */
            virtual std::unique_ptr<ResultPackage> receive_result_package(
                std::shared_ptr<seal::SEALContext> context) = 0;

            /**
            Get the amount of data that has been sent through the channel.
            */
            std::uint64_t bytes_sent() const
            {
                return bytes_sent_;
            }

            /**
            Get the amount of data that has been received through the channel.
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
