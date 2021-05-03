// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
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
class CLP : public BaseCLP {
public:
    CLP(const std::string &desc, const std::string &version) : BaseCLP(desc, version)
    {}

    virtual void add_args()
    {
        add(compress_arg_);
        add(nonce_byte_count_arg_);
        add(net_port_arg_);
        add(params_file_arg_);
        add(db_file_arg_);
        add(sdb_out_file_arg_);
    }

    virtual void get_args()
    {
        compress_ = compress_arg_.getValue();
        nonce_byte_count_ = nonce_byte_count_arg_.getValue();
        db_file_ = db_file_arg_.isSet() ? db_file_arg_.getValue() : "";
        net_port_ = net_port_arg_.getValue();
        params_file_ = params_file_arg_.getValue();
        sdb_out_file_ = sdb_out_file_arg_.getValue();
    }

    std::size_t nonce_byte_count() const
    {
        return nonce_byte_count_;
    }

    bool compress() const
    {
        return compress_;
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

    const std::string &sdb_out_file() const
    {
        return sdb_out_file_;
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
        "", "port", "TCP port to bind to (default is 1212)", false, 1212, "TCP port");

    TCLAP::ValueArg<std::string> db_file_arg_ = TCLAP::ValueArg<std::string>(
        "d",
        "dbFile",
        "Path to a saved SenderDB file or a CSV file describing the sender's dataset (an "
        "item-label pair on each row)",
        true,
        "",
        "string");

    TCLAP::ValueArg<std::string> params_file_arg_ = TCLAP::ValueArg<std::string>(
        "p",
        "paramsFile",
        "Path to a JSON file that specifies APSI parameters; this must be given if --dbFile is "
        "specified with a path "
        "to a CSV file",
        false,
        "",
        "string");

    TCLAP::ValueArg<std::string> sdb_out_file_arg_ = TCLAP::ValueArg<std::string>(
        "o", "sdbOutFile", "Save the SenderDB in the given file", false, "", "string");

    TCLAP::SwitchArg compress_arg_ =
        TCLAP::SwitchArg("c", "compress", "Whether to compress the SenderDB in memory", false);

    std::size_t nonce_byte_count_;

    bool compress_;

    int net_port_;

    std::string db_file_;

    std::string params_file_;

    std::string sdb_out_file_;
};
