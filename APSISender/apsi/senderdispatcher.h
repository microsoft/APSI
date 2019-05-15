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
    namespace sender
    {
        /**
        The Sender Dispatcher is in charge of handling incoming requests through the network.
        */
        class SenderDispatcher
        {
        public:
            SenderDispatcher() = delete;
            SenderDispatcher(std::shared_ptr<apsi::sender::Sender> sender)
                : sender_(sender)
            {}

            /**
            Run the dispatcher on the given port.
            */
            void run(const std::atomic<bool>& stop, const int port);

        private:
            std::shared_ptr<apsi::sender::Sender> sender_;

            /**
            Dispatch a Get Parameters request to the Sender.
            */
            void dispatch_get_parameters(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);

            /**
            Dispatch a Preprocess request to the Sender.
            */
            void dispatch_preprocess(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);

            /**
            Dispatch a Query request to the Sender.
            */
            void dispatch_query(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);
        };
    }
}
