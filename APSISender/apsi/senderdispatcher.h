// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <memory>

// APSI
#include "apsi/network/senderoperation.h"
#include "apsi/network/channel.h"
#include "apsi/sender.h"


namespace apsi
{
    namespace oprf
    {
        class OPRFKey;
    }

    namespace sender
    {
        /**
        The Sender Dispatcher is in charge of handling incoming requests through the network.
        */
        class SenderDispatcher
        {
        public:
            SenderDispatcher() = delete;
            SenderDispatcher(std::shared_ptr<sender::Sender> sender)
                : sender_(sender)
            {}

            /**
            Run the dispatcher on the given port.
            */
            void run(const std::atomic<bool>& stop, int port, const std::shared_ptr<oprf::OPRFKey>& oprf_key);

        private:
            std::shared_ptr<sender::Sender> sender_;
            std::shared_ptr<oprf::OPRFKey> oprf_key_;

            /**
            Dispatch a Get Parameters request to the Sender.
            */
            void dispatch_get_parameters(std::shared_ptr<network::SenderOperation> sender_op, network::Channel& channel);

            /**
            Dispatch a Preprocess request to the Sender.
            */
            void dispatch_preprocess(std::shared_ptr<network::SenderOperation> sender_op, network::Channel& channel);

            /**
            Dispatch a Query request to the Sender.
            */
            void dispatch_query(std::shared_ptr<network::SenderOperation> sender_op, network::Channel& channel);
        }; // class SenderDispatcher
    } // namespace sender
} // namespace apsi
