// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>

// Base
#include "common/base_clp.h"

/**
Command Line Processor for Receiver.
*/
class CLP : public BaseCLP {
public:
    CLP(const std::string &desc, const std::string &version) : BaseCLP(desc, version)
    {}

    virtual void add_args()
    {
        add(net_addr_arg_);
        add(net_port_arg_);
        add(query_file_arg_);
        add(out_file_arg_);
    }

    virtual void get_args()
    {
        net_addr_ = net_addr_arg_.getValue();
        net_port_ = net_port_arg_.getValue();
        query_file_ = query_file_arg_.getValue();
        output_file_ = out_file_arg_.getValue();
    }

    const std::string &net_addr() const
    {
        return net_addr_;
    }

    int net_port() const
    {
        return net_port_;
    }

    const std::string &query_file() const
    {
        return query_file_;
    }

    const std::string &output_file() const
    {
        return output_file_;
    }

private:
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

    std::string net_addr_;

    int net_port_;

    std::string query_file_;

    std::string output_file_;
};
