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
        add(felts_per_item_arg_);
        add(table_size_arg_);
        add(max_item_per_bin_arg_);
        add(hash_func_count_arg_);
        add(query_powers_arg_);
        add(poly_modulus_degree_arg_);
        add(coeff_modulus_bits_arg_);
        xorAdd(plain_modulus_bits_arg_, plain_modulus_arg_);
        add(nonce_byte_count_arg_);
        add(net_port_arg_);
        add(db_file_arg_);
    }

    virtual void get_args()
    {
        felts_per_item_ = felts_per_item_arg_.getValue();
        table_size_ = table_size_arg_.getValue();
        max_items_per_bin_ = max_item_per_bin_arg_.getValue();
        hash_func_count_ = hash_func_count_arg_.getValue();

        std::vector<std::uint32_t> query_powers_vec = query_powers_arg_.getValue();
        query_powers_vec.push_back(1);
        std::copy(query_powers_vec.cbegin(), query_powers_vec.cend(), inserter(query_powers_, query_powers_.end()));

        poly_modulus_degree_ = poly_modulus_degree_arg_.getValue();
        coeff_modulus_bits_ = coeff_modulus_bits_arg_.getValue();

        if (plain_modulus_bits_arg_.isSet())
        {
            plain_modulus_bits_ = plain_modulus_bits_arg_.getValue();
        }
        else if (plain_modulus_arg_.isSet())
        {
            plain_modulus_ = plain_modulus_arg_.getValue();
            plain_modulus_bits_ = plain_modulus_.bit_count();
        }

        nonce_byte_count_ = nonce_byte_count_arg_.getValue();
        db_file_ = db_file_arg_.getValue();
        net_port_ = net_port_arg_.getValue();
    }

    std::uint32_t felts_per_item() const
    {
        return felts_per_item_;
    }

    std::uint32_t table_size() const
    {
        return table_size_;
    }

    std::uint32_t max_items_per_bin() const
    {
        return max_items_per_bin_;
    }

    std::uint32_t hash_func_count() const
    {
        return hash_func_count_;
    }

    const std::set<std::uint32_t> &query_powers() const
    {
        return query_powers_;
    }

    std::size_t poly_modulus_degree() const
    {
        return poly_modulus_degree_;
    }

    const std::vector<int> &coeff_modulus_bits() const
    {
        return coeff_modulus_bits_;
    }

    int plain_modulus_bits() const
    {
        return plain_modulus_bits_;
    }

    const seal::Modulus &plain_modulus() const
    {
        return plain_modulus_;
    }

    std::size_t nonce_byte_count() const
    {
        return nonce_byte_count_;
    }

    int net_port() const
    {
        return net_port_;
    }

    const std::string &db_file () const
    {
        return db_file_;
    }

private:
    TCLAP::ValueArg<std::uint32_t> felts_per_item_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "F",
        "feltsPerItem",
        "Number of fields elements to use per item",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::uint32_t> table_size_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "T",
        "tableSize",
        "Size of the hash table to use",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::uint32_t> max_item_per_bin_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "m",
        "maxItemsPerBin",
        "Maximum number of items allowed in a bin",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::uint32_t> hash_func_count_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "H",
        "hashFuncCount",
        "Maximum number of items allowed in a bin",
        true,
        0,
        "unsigned integer");

    TCLAP::MultiArg<std::uint32_t> query_powers_arg_ = TCLAP::MultiArg<std::uint32_t>(
        "w",
        "queryPowers",
        "Query powers to send in addition to 1",
        false,
        "unsigned integer");

    TCLAP::ValueArg<std::size_t> poly_modulus_degree_arg_ = TCLAP::ValueArg<std::size_t>(
        "P",
        "polyModulusDegree",
        "Degree of the polynomial modulus for Microsoft SEAL encryption",
        true,
        0,
        "unsigned integer");

    TCLAP::MultiArg<int> coeff_modulus_bits_arg_ = TCLAP::MultiArg<int>(
        "C",
        "coeffModulusBits",
        "Bit sizes for coefficient modulus primes for Microsoft SEAL encryption",
        true,
        "list of unsigned integers");

    TCLAP::ValueArg<int> plain_modulus_bits_arg_ = TCLAP::ValueArg<int>(
        "a",
        "plainModulusBits",
        "Bit size for plaintext modulus prime for Microsoft SEAL encryption",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::uint64_t> plain_modulus_arg_ = TCLAP::ValueArg<std::uint64_t>(
        "A",
        "plainModulus",
        "Plaintext modulus prime for Microsoft SEAL encryption",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::size_t> nonce_byte_count_arg_ = TCLAP::ValueArg<std::size_t>(
        "n",
        "nonceByteCount",
        "Number of bytes used for the nonce in labeled mode",
        false,
        16,
        "unsigned integer");

    TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>(
        "",
        "port",
        "Network port to bind to",
        false,
        1212,
        "TCP port"
    );

    TCLAP::ValueArg<std::string> db_file_arg_ = TCLAP::ValueArg<std::string>(
        "d",
        "dbFile",
        "Path to a CSV file containing the database",
        true,
        "",
        "string"
    );

    std::uint32_t felts_per_item_;

    std::uint32_t table_size_;

    std::uint32_t max_items_per_bin_;

    std::uint32_t hash_func_count_;

    std::set<std::uint32_t> query_powers_;

    std::size_t poly_modulus_degree_;

    std::vector<int> coeff_modulus_bits_;

    int plain_modulus_bits_;

    seal::Modulus plain_modulus_;

    std::size_t nonce_byte_count_;

    int net_port_;

    std::string db_file_;
};
