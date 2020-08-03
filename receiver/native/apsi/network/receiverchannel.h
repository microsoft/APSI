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
        Represents a network channel for a receiver.
        */
        class ReceiverChannel : public NetworkChannel
        {
        public:
            ReceiverChannel() = default;

        protected:
            /**
            The only difference from a sender is the socket type.
            */
            virtual zmqpp::socket_type get_socket_type();

            /**
            The receiver needs to set a couple of socket options to ensure messages are not dropped.
            */
            virtual void set_socket_options(zmqpp::socket_t *socket);
        };
    } // namespace network
} // namespace apsi
