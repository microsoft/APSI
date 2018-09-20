#pragma once

// STD
#include <atomic>
#include <memory>

// APSI
#include "apsi/network/senderoperation.h"

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
            void DispatchGetParameters(const std::shared_ptr<apsi::network::SenderOperation> sender_op);
            void DispatchPreprocess(const std::shared_ptr<apsi::network::SenderOperation> sender_op);
            void DispatchQuery(const std::shared_ptr<apsi::network::SenderOperation> sender_op);
        };
    }
}
