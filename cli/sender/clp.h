// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <vector>

// APSI
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
        add(query_powers_count_arg_);
        add(poly_modulus_degree_arg_);
        add(coeff_modulus_bits_arg_);
        xorAdd(plain_modulus_bits_arg_, plain_modulus_arg_);
        add(net_port_arg_);
        add(db_file_arg_);
    }

    virtual void get_args()
    {
        felts_per_item_ = felts_per_item_arg_.getValue();
        cout_param("feltsPerItem", felts_per_item_);

        table_size_ = table_size_arg_.getValue();
        cout_param("tableSize", table_size_);

        max_items_per_bin_ = max_item_per_bin_arg_.getValue();
        cout_param("maxItemsPerBin", max_items_per_bin_);

        hash_func_count_ = hash_func_count_arg_.getValue();
        cout_param("hashFuncCount", hash_func_count_);

        query_powers_count_ = query_powers_count_arg_.getValue();
        cout_param("queryPowersCount", query_powers_count_);

        powers_dag_seed_ = powers_dag_seed_arg_.getValue();
        cout_param("powersDagSeed", powers_dag_seed_);

        poly_modulus_degree_ = poly_modulus_degree_arg_.getValue();
        cout_param("polyModulusDegree", poly_modulus_degree_);

        coeff_modulus_bits_ = coeff_modulus_bits_arg_.getValue();
        std::string coeff_modulus_bits_str;
        if (coeff_modulus_bits_.size() == 0)
        {
            coeff_modulus_bits_str = "N/A";
        }
        else
        {
            std::ostringstream ss;
            for (auto &coeff : coeff_modulus_bits_)
            {
                ss << coeff << ", ";
            }
            coeff_modulus_bits_str = ss.str();
        }
        cout_param("coeffModulusBits", coeff_modulus_bits_str);

        if (plain_modulus_bits_arg_.isSet())
        {
            plain_modulus_bits_ = plain_modulus_bits_arg_.getValue();
            cout_param("plainModulusBits", plain_modulus_bits_);
        }
        else if (plain_modulus_arg_.isSet())
        {
            plain_modulus_ = plain_modulus_arg_.getValue();
            plain_modulus_bits_ = plain_modulus_.bit_count();
            cout_param("plainModulusBits", plain_modulus_bits_);
        }

        db_file_ = db_file_arg_.getValue();
        cout_param("dbFile", db_file_);

        net_port_ = net_port_arg_.getValue();
        cout_param("port", net_port_);
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

    std::uint32_t query_powers_count() const
    {
        return query_powers_count_;
    }

    std::uint32_t powers_dag_seed() const
    {
        return powers_dag_seed_;
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

    TCLAP::ValueArg<std::uint32_t> query_powers_count_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "w",
        "queryPowersCount",
        "The number of query powers sent",
        true,
        0,
        "unsigned integer");

    TCLAP::ValueArg<std::uint32_t> powers_dag_seed_arg_ = TCLAP::ValueArg<std::uint32_t>(
        "s",
        "powersDagSeed",
        "32-bit seed for creating the PowersDag",
        true,
        0,
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

    std::uint32_t query_powers_count_;

    std::uint32_t powers_dag_seed_;

    std::size_t poly_modulus_degree_;

    std::vector<int> coeff_modulus_bits_;

    int plain_modulus_bits_;

    seal::Modulus plain_modulus_;

    int net_port_;

    std::string db_file_;
};
