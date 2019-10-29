// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "base_clp.h"

namespace apsi
{
    /**
    Command Line Processor for Sender
    */
    class CLP : public BaseCLP
    {
    public:
        CLP(const std::string& desc, const std::string& version)
            : BaseCLP(desc, version)
        {}

        virtual void add_args()
        {
            add(labels_arg_);
            add(fast_membership_arg_);
            add(item_bit_length_arg_);
            add(sec_lvl_arg_);
            add(log_tbl_sz_arg_);
            add(split_cnt_arg_);
            add(split_sz_arg_);
            add(wnd_sz_arg_);
            add(poly_mod_arg_);
            add(coeff_mod_arg_);
            add(plain_mod_arg_);
            add(exfld_degree_arg_);
            add(db_file_arg_);
            add(net_port_arg_);
            add(num_chunks_arg_); 
            add(sender_bin_size_arg_);
            add(item_bit_length_used_after_oprf_arg_); 
            add(hash_func_count_arg_); 
        }

        virtual void get_args()
        {
            use_labels_ = labels_arg_.getValue();
            cout_param("useLabels", use_labels_ ? "true" : "false");

            fast_membership_ = fast_membership_arg_.getValue();
            cout_param("fast membership",  fast_membership_? "true" : "false");

            item_bit_length_ = item_bit_length_arg_.getValue();
            cout_param("itemBitLength", item_bit_length_);

            item_bit_length_used_after_oprf_ = item_bit_length_used_after_oprf_arg_.getValue();
            cout_param("itemBitLengthUsedAfterOPRF", item_bit_length_used_after_oprf_);

            sec_level_ = sec_lvl_arg_.getValue();
            cout_param("secLevel", sec_level_);

            log_table_size_ = log_tbl_sz_arg_.getValue();
            cout_param("logTableSize", log_table_size_);

            split_count_ = split_cnt_arg_.getValue();
            cout_param("splitCount", split_count_);

            split_size_ = split_sz_arg_.getValue();
            cout_param("splitSize", split_size_);

            window_size_ = wnd_sz_arg_.getValue();
            cout_param("windowSize", window_size_);

            poly_modulus_ = poly_mod_arg_.getValue();
            cout_param("polyModulus", poly_modulus_);

            coeff_modulus_ = coeff_mod_arg_.getValue();
            std::string coeffVal;
            if (coeff_modulus_.size() == 0)
            {
                coeffVal = "N/A";
            }
            else
            {
                std::ostringstream ss;
                for (auto& coeff : coeff_modulus_)
                {
                    ss << coeff << ", ";
                }
                coeffVal = ss.str();
            }
            cout_param("coeffModulus", coeffVal);

            plain_modulus_ = plain_mod_arg_.getValue();
            cout_param("plainModulus", plain_modulus_);

            exfield_degree_ = exfld_degree_arg_.getValue();
            cout_param("exfieldDegree", exfield_degree_);

            db_file_ = db_file_arg_.getValue();
            cout_param("db", db_file_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);

            num_chunks_ = num_chunks_arg_.getValue();
            cout_param("numChunks", num_chunks_);

            sender_bin_size_ = sender_bin_size_arg_.getValue();
            cout_param("senderBinSize", sender_bin_size_);

            hash_func_count_ = hash_func_count_arg_.getValue();
            cout_param("numHashes", hash_func_count_);
        }

        bool use_labels() const { return use_labels_; }
        bool use_fast_memberhip() const { return fast_membership_; }

        apsi::u32 item_bit_length() const { return item_bit_length_; }
        apsi::u32 sec_level() const { return sec_level_; }
        int log_table_size() const { return log_table_size_; }
        int split_count() const { return split_count_; }
        int split_size() const { return split_size_; }
        

        int window_size() const { return window_size_; }
        int poly_modulus() const { return poly_modulus_; }
        const std::vector<u64>& coeff_modulus() const { return coeff_modulus_; }
        apsi::u64 plain_modulus() const { return plain_modulus_; }
        int exfield_degree() const { return exfield_degree_; }
        int net_port() const { return net_port_; }
        const std::string& db_file() const { return db_file_; }
        int num_chunks() const { return num_chunks_; }	
        int sender_bin_size() const { return sender_bin_size_; }
        int hash_func_count() const { return hash_func_count_; }

        apsi::u32 item_bit_length_used_after_oprf() const { return item_bit_length_used_after_oprf_; }

    private:
        TCLAP::SwitchArg             labels_arg_          = TCLAP::SwitchArg("l", "useLabels", "Use labels", false);
        TCLAP::SwitchArg             fast_membership_arg_ = TCLAP::SwitchArg("f", "fastMembership", "Use fast membership", false);
        TCLAP::ValueArg<apsi::u32>   item_bit_length_arg_ = TCLAP::ValueArg<apsi::u32>("b", "itemBitLength", "Item bit length", false, 60, "unsigned");
        TCLAP::ValueArg<int>         net_port_arg_        = TCLAP::ValueArg<int>("", "port", "Network port to bind to", false, 1212, "int");
        TCLAP::ValueArg<std::string> db_file_arg_         = TCLAP::ValueArg<std::string>("", "db", "Path to the file containing the Sender database", true, "", "string");
        TCLAP::ValueArg<apsi::u32>   sec_lvl_arg_         = TCLAP::ValueArg<apsi::u32>("", "secLevel", "Security level", false, 40, "unsigned");
        TCLAP::ValueArg<int>         log_tbl_sz_arg_      = TCLAP::ValueArg<int>("", "logTableSize", "Table Size", false, 9, "int");
        TCLAP::ValueArg<int>         split_cnt_arg_       = TCLAP::ValueArg<int>("", "splitCount", "Split count", false, 1, "int");
        TCLAP::ValueArg<int>         split_sz_arg_ = TCLAP::ValueArg<int>("", "splitSize", "Split size", false, 15, "int");
        TCLAP::ValueArg<int>         wnd_sz_arg_          = TCLAP::ValueArg<int>("w", "windowSize", "Window size", false, 1, "int");
        TCLAP::ValueArg<int>         poly_mod_arg_        = TCLAP::ValueArg<int>("", "polyModulus", "Poly Modulus degree", false, 4096, "int");

        TCLAP::MultiArg<apsi::u64>   coeff_mod_arg_ =   TCLAP::MultiArg<apsi::u64>("c", "coeffModulus", "Coefficient Modulus", false, "u64");
        TCLAP::ValueArg<apsi::u64>   plain_mod_arg_       = TCLAP::ValueArg<apsi::u64>("", "plainModulus", "Plain Modulus", false, 40961, "u64");
        TCLAP::ValueArg<int>         exfld_degree_arg_    = TCLAP::ValueArg<int>("e", "exfieldDegree", "exField degree", false, 8, "int");
        TCLAP::ValueArg<int>         num_chunks_arg_      = TCLAP::ValueArg<int>("", "numChunks", "number of chunks per item", false, 1, "int");
        TCLAP::ValueArg<int>         sender_bin_size_arg_ = TCLAP::ValueArg<int>("", "senderBinSize", "(manually set) sender bin size", false, 0, "int");
        TCLAP::ValueArg<int>         hash_func_count_arg_ = TCLAP::ValueArg<int>("", "numHashes", "number of hash functions in cuckoo hashing", false, 2, "int");
        TCLAP::ValueArg<apsi::u32>   item_bit_length_used_after_oprf_arg_
                                                          = TCLAP::ValueArg<apsi::u32>("i", "itemBitLengthUsedAfterOPRF", "Item bit length used after oprf", false, 120, "unsigned");

        bool use_labels_;
        bool fast_membership_;
        apsi::u32 item_bit_length_;
        apsi::u32 sec_level_;
        int log_table_size_;
        int split_count_;
        int split_size_;
        int window_size_;
        int poly_modulus_;
        std::vector<u64> coeff_modulus_;
        apsi::u64 plain_modulus_;
        int exfield_degree_;
        int net_port_;
        std::string db_file_;
        int num_chunks_;
        int sender_bin_size_;
        int hash_func_count_;
        apsi::u32 item_bit_length_used_after_oprf_;
    };
}
