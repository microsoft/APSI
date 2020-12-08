// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <memory>
#include <utility>

// APSI
#include "apsi/network/zmq/network_channel.h"
#include "apsi/network/sender_operation.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/sender.h"
#include "apsi/senderdb.h"

namespace apsi
{
    namespace sender
    {
        /**
        The Sender Dispatcher is in charge of handling incoming requests through the network.
        */
        class SenderDispatcher
        {
        public:
            SenderDispatcher() = delete;

            SenderDispatcher(std::shared_ptr<SenderDB> sender_db, std::size_t thread_count = 0);

            /**
            Run the dispatcher on the given port.
            */
            void run(
                const std::atomic<bool> &stop, int port, std::shared_ptr<const oprf::OPRFKey> oprf_key);

        private:
            std::shared_ptr<sender::SenderDB> sender_db_;

            std::size_t thread_count_;

            std::shared_ptr<const oprf::OPRFKey> oprf_key_;

            /**
            Dispatch a Get Parameters request to the Sender.
            */
            void dispatch_parms(std::unique_ptr<network::NetworkSenderOperation> sop, network::SenderChannel &channel);

            /**
            Dispatch an OPRF query request to the Sender.
            */
            void dispatch_oprf(std::unique_ptr<network::NetworkSenderOperation> sop, network::SenderChannel &channel);

            /**
            Dispatch a Query request to the Sender.
            */
            void dispatch_query(std::unique_ptr<network::NetworkSenderOperation> sop, network::SenderChannel &channel);
        }; // class SenderDispatcher
    }      // namespace sender
} // namespace apsi