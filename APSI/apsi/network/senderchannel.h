#pragma once 

// APSI
#include "apsi/network/channel.h"

namespace apsi
{
    namespace network
    {
        class SenderChannel : public Channel
        {
        public:
            SenderChannel() = delete;
            SenderChannel(const zmqpp::context_t& context)
                : Channel(context)
            {}

        protected:
            virtual zmqpp::socket_type get_socket_type()
            {
                return zmqpp::socket_type::reply;
            }
        };
    }
}
