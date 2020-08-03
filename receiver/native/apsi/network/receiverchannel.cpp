// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/network/receiverchannel.h"

// ZeroMQ
#pragma warning(push, 0)
#include "zmqpp/zmqpp.hpp"
#pragma warning(pop)

using namespace zmqpp;

namespace apsi
{
    namespace network
    {
        socket_type ReceiverChannel::get_socket_type()
        {
            return socket_type::dealer;
        }

        void ReceiverChannel::set_socket_options(socket_t *socket)
        {
            // Ensure messages are not dropped
            socket->set(socket_option::receive_high_water_mark, 70000);
        }
    } // namespace network
} // namespace apsi
