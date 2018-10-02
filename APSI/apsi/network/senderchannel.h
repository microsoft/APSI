#pragma once 

// APSI
#include "apsi/network/channel.h"

namespace apsi
{
    namespace network
    {
        /**
        Represents a network channel for a Sender.
        */
        class SenderChannel : public Channel
        {
        public:
            SenderChannel() = delete;
            SenderChannel(const zmqpp::context_t& context)
                : Channel(context)
            {}

        protected:
            /**
            The only difference from a Receiver is the socket type.
            */
            virtual zmqpp::socket_type get_socket_type()
            {
                return zmqpp::socket_type::router;
            }
        };
    }
}
