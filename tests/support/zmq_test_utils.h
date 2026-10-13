// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <exception>
#include <future>
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

    /**
    Stops a dispatcher running on another thread and waits for it, on every exit path.

    A test body leaves through a fatal assertion or a thrown exception as readily as it leaves
    through its last statement, and a dispatcher loops until it is told to stop. Stopping it from
    the end of the body therefore only covers the case where nothing went wrong: any other exit
    leaves the loop running and blocks the destructor of the future that holds it, so the binary
    stops producing output instead of reporting which assertion failed. A failure of the
    dispatcher itself is dropped here, so a test that is to report one stops the dispatcher and
    waits for it before it ends.
    */
    class DispatcherStopper {
    public:
        DispatcherStopper(std::atomic<bool> &stop, std::future<void> &running)
            : stop_(stop), running_(running)
        {}

        DispatcherStopper(const DispatcherStopper &) = delete;

        DispatcherStopper &operator=(const DispatcherStopper &) = delete;

        ~DispatcherStopper()
        {
            stop_ = true;
            if (running_.valid()) {
                try {
                    running_.get();
                } catch (const std::exception &) { // NOLINT(bugprone-empty-catch): see below
                    // The dispatcher's own failure must not replace the assertion that is
                    // already on its way out, and must not leave the process by way of a
                    // destructor.
                }
            }
        }

    private:
        std::atomic<bool> &stop_;

        std::future<void> &running_;
    }; // class DispatcherStopper
} // namespace APSITests
