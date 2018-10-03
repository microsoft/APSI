#pragma once 

// APSI
#include "apsi/network/channel.h"

namespace apsi
{
    namespace network
    {
        /**
        Represents a network channel for a Receiver.
        */
        class ReceiverChannel : public Channel
        {
        public:
            ReceiverChannel() = delete;
            ReceiverChannel(const zmqpp::context_t& context)
                : Channel(context)
            {}

        protected:
            /**
            The only difference from a Sender is the socket type.
            */
            virtual zmqpp::socket_type get_socket_type()
            {
                return zmqpp::socket_type::dealer;
            }
        };
    }
}
