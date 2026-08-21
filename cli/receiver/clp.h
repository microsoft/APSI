// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <chrono>
#include <cstddef>
#include <string>

// APSI
#include "apsi/receiver.h"

// Base
#include "common/base_clp.h"

/**
Bounds the accepted timeout to a range that survives the conversion to milliseconds.

The command line is parsed into an unsigned type, so a negative number arrives as a very large
positive one rather than as a parse error, and an unchecked conversion to milliseconds would
overflow. Either way the deadline that took effect would bear no relation to the one asked for: a
negative number wraps to a deadline already in the past, and a large positive one to an arbitrary
shorter or longer wait. Both are refused here so the operator is told, rather than silently given
something else. Waiting forever stays available as an explicit 0.
*/
class TimeoutConstraint : public TCLAP::Constraint<std::size_t> {
public:
    static constexpr std::size_t max_seconds = static_cast<std::size_t>(365) * 24 * 60 * 60;

    [[nodiscard]] std::string description() const override
    {
        return "0 to " + std::to_string(max_seconds) + " seconds";
    }

    [[nodiscard]] std::string shortID() const override
    {
        return "unsigned integer";
    }

    [[nodiscard]] bool check(const std::size_t &value) const override
    {
        return value <= max_seconds;
    }
};

/**
Command Line Processor for Receiver.
*/
class CLP : public BaseCLP {
public:
    CLP(const std::string &desc, const std::string &version) : BaseCLP(desc, version)
    {}

    void add_args() override
    {
        add(net_addr_arg_);
        add(net_port_arg_);
        add(query_file_arg_);
        add(out_file_arg_);
        add(timeout_arg_);
    }

    void get_args() override
    {
        net_addr_ = net_addr_arg_.getValue();
        net_port_ = net_port_arg_.getValue();
        query_file_ = query_file_arg_.getValue();
        output_file_ = out_file_arg_.getValue();
        timeout_ = std::chrono::seconds(timeout_arg_.getValue());
    }

    [[nodiscard]] const std::string &net_addr() const
    {
        return net_addr_;
    }

    [[nodiscard]] int net_port() const
    {
        return net_port_;
    }

    [[nodiscard]] const std::string &query_file() const
    {
        return query_file_;
    }

    [[nodiscard]] const std::string &output_file() const
    {
        return output_file_;
    }

    /**
    How long to wait on a silent sender before giving up. Zero means wait indefinitely.
    */
    [[nodiscard]] std::chrono::milliseconds timeout() const
    {
        return timeout_;
    }

private:
    // Kept in step with the library default rather than restated, so the two cannot drift.
    static constexpr std::size_t default_timeout_seconds =
        static_cast<std::size_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     apsi::receiver::Receiver::default_receive_timeout)
                                     .count());

    // duration_cast truncates toward zero, and zero is the value that disables the deadline
    // altogether. A sub-second library default would therefore arrive here as "wait forever",
    // turning the control off in the one place nothing else would notice, since TCLAP does not
    // run a constraint against an argument's default value.
    static_assert(
        default_timeout_seconds > 0,
        "Receiver::default_receive_timeout must be at least one second, or the CLI default "
        "truncates to zero and disables the receive deadline");

    TCLAP::ValueArg<std::string> net_addr_arg_ = TCLAP::ValueArg<std::string>(
        "a", "ipAddr", "IP address for a sender endpoint", false, "localhost", "string");

    TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>(
        "", "port", "TCP port to connect to (default is 1212)", false, 1212, "TCP port");

    TCLAP::ValueArg<std::string> query_file_arg_ = TCLAP::ValueArg<std::string>(
        "q",
        "queryFile",
        "Path to a text file containing query data (one per line)",
        true,
        "",
        "string");

    TCLAP::ValueArg<std::string> out_file_arg_ = TCLAP::ValueArg<std::string>(
        "o",
        "outFile",
        "Path to a file where intersection result will be written",
        false,
        "",
        "string");

    // The default mirrors Receiver::default_receive_timeout. It bounds silence, not the length
    // of the query, so raising it is only necessary when a sender can legitimately pause for
    // minutes at a time; 0 disables the deadline and waits forever.
    TimeoutConstraint timeout_constraint_;

    TCLAP::ValueArg<std::size_t> timeout_arg_ = TCLAP::ValueArg<std::size_t>(
        "",
        "timeout",
        "Seconds of sender silence to tolerate before giving up (default is " +
            std::to_string(default_timeout_seconds) +
            "). Every message received restarts the clock, so a slow but responsive sender is "
            "never cut off; 0 waits forever",
        false,
        default_timeout_seconds,
        &timeout_constraint_);

    std::string net_addr_;

    int net_port_{};

    std::string query_file_;

    std::string output_file_;

    std::chrono::milliseconds timeout_{};
};
