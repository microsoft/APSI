// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <set>
#include <vector>

// APSI
#include "apsi/util/utils.h"
#include "common/base_clp.h"

// SEAL
#include "seal/modulus.h"

/**
Command Line Processor for Sender.
*/
class CLP : public BaseCLP
{
public:
    CLP(const std::string &desc, const std::string &version) : BaseCLP(desc, version)
    {}

    virtual void add_args()
    {
        add(nonce_byte_count_arg_);
        add(net_port_arg_);
        add(params_file_arg_);
        xorAdd(db_file_arg_, sender_db_load_file_arg_);
        add(sender_db_save_file_arg_);
    }

    virtual void get_args()
    {
        nonce_byte_count_ = nonce_byte_count_arg_.getValue();
        db_file_ = db_file_arg_.isSet() ? db_file_arg_.getValue() : "";
        net_port_ = net_port_arg_.getValue();
        params_file_ = params_file_arg_.getValue();
        sender_db_load_file_ = sender_db_load_file_arg_.isSet() ? sender_db_load_file_arg_.getValue() : "";
        sender_db_save_file_ = sender_db_save_file_arg_.getValue();
    }

    std::size_t nonce_byte_count() const
    {
        return nonce_byte_count_;
    }

    int net_port() const
    {
        return net_port_;
    }

    const std::string &db_file() const
    {
        return db_file_;
    }

    const std::string &params_file() const
    {
        return params_file_;
    }

    const std::string &sender_db_save_file() const
    {
        return sender_db_save_file_;
    }

    const std::string &sender_db_load_file() const
    {
        return sender_db_load_file_;
    }

private:
    TCLAP::ValueArg<std::size_t> nonce_byte_count_arg_ = TCLAP::ValueArg<std::size_t>(
        "n",
        "nonceByteCount",
        "Number of bytes used for the nonce in labeled mode (default is 16)",
        false,
        16,
        "unsigned integer");

    TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>(
        "",
        "port",
        "TCP port to bind to (default is 1212)",
        false,
        1212,
        "TCP port"
    );

    TCLAP::ValueArg<std::string> db_file_arg_ = TCLAP::ValueArg<std::string>(
        "d",
        "dbFile",
        "Path to a CSV file describing the sender's dataset (an item-label pair on each row)",
        true,
        "",
        "string"
    );

    TCLAP::ValueArg<std::string> params_file_arg_ = TCLAP::ValueArg<std::string>(
        "",
        "paramsFile",
        "Path to a JSON file that specifies APSI parameters",
        true,
        "",
        "string"
    );

    TCLAP::ValueArg<std::string> sender_db_load_file_arg_ = TCLAP::ValueArg<std::string>(
        "",
        "loadSenderDB",
        "File to load the SenderDB from",
        true,
        "",
        "string"
    );

    TCLAP::ValueArg<std::string> sender_db_save_file_arg_ = TCLAP::ValueArg<std::string>(
        "",
        "saveSenderDB",
        "File to save the SenderDB to",
        false,
        "",
        "string"
    );

    std::size_t nonce_byte_count_;

    int net_port_;

    std::string db_file_;

    std::string params_file_;

    std::string sender_db_load_file_;

    std::string sender_db_save_file_;
};
