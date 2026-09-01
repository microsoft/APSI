// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <stdexcept>
#include <string>

// APSI
#include "apsi/network/zmq/zmq_channel.h"

namespace APSITests {
    /**
    Bind address that leaves the choice of port to the operating system.

    Tests must not hard-code a port. A fixed one collides with a second test binary running at
    the same time, with a Debug and a Release run sharing a machine, with a leftover process
    still holding the port, and with anything else that happens to want it. The collision
    surfaces as an unrelated test failing to bind, which is a confusing way to learn that two
    runs overlapped.
    */
    inline const char *any_port_bind_address()
    {
        return "tcp://*:0";
    }

    /**
    The port a bound channel actually received, taken from the endpoint ZeroMQ reports.
    */
    inline int bound_port(const apsi::network::ZMQChannel &chl)
    {
        const std::string &end_point = chl.end_point();
        std::size_t colon = end_point.find_last_of(':');
        if (colon == std::string::npos || colon + 1 == end_point.size()) {
            throw std::runtime_error("channel is not bound to a TCP endpoint: " + end_point);
        }

        return std::stoi(end_point.substr(colon + 1));
    }

    /**
    Address to connect to in order to reach a channel bound to the given port.
    */
    inline std::string connect_address(int port)
    {
        return "tcp://localhost:" + std::to_string(port);
    }

    /**
    Address to connect to in order to reach the given bound channel.
    */
    inline std::string connect_address(const apsi::network::ZMQChannel &chl)
    {
        return connect_address(bound_port(chl));
    }
} // namespace APSITests
