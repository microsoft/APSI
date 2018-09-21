#pragma once

// STD
#include <atomic>
#include <memory>

// APSI
#include "apsi/network/senderoperation.h"
#include "apsi/network/channel.h"
#include "apsi/sender/sender.h"


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
            /**
            Run the dispatcher on the given port.
            */
            void run(const std::atomic<bool>& stop, int port);

        private:
            std::shared_ptr<apsi::sender::Sender> sender_;

            void dispatch_get_parameters(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);
            void dispatch_preprocess(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);
            void dispatch_query(std::shared_ptr<apsi::network::SenderOperation> sender_op, apsi::network::Channel& channel);
        };
    }
}
