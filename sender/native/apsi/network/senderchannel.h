// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// APSI
#include "apsi/network/network_channel.h"

namespace apsi
{
    namespace network
    {
        /**
        Represents a network channel for a Sender.
        */
        class SenderChannel : public NetworkChannel
        {
        public:
            SenderChannel() = default;

        protected:
            /**
            The only difference from a Receiver is the socket type.
            */
            virtual zmqpp::socket_type get_socket_type();

            /**
            The Sender needs to set a couple of socket options to ensure
            messages are not dropped.
            */
            virtual void set_socket_options(zmqpp::socket_t *socket);
        };
    } // namespace network
} // namespace apsi
