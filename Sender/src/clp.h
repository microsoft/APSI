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
            add(oprf_arg_);
            add(item_bit_length_arg_);
            add(sec_lvl_arg_);
            add(log_tbl_sz_arg_);
            add(split_cnt_arg_);
            add(wnd_sz_arg_);
            add(poly_mod_arg_);
            add(coeff_mod_arg_);
            add(plain_mod_arg_);
            add(dbc_arg_);
            add(exfld_degree_arg_);
            add(db_file_arg_);
            add(net_port_arg_);
        }

        virtual void get_args()
        {
            use_labels_ = labels_arg_.getValue();
            cout_param("useLabels", use_labels_ ? "true" : "false");

            oprf_ = oprf_arg_.getValue();
            cout_param("oprf", oprf_ ? "true" : "false");

            item_bit_length_ = item_bit_length_arg_.getValue();
            cout_param("itemBitLength", item_bit_length_);

            sec_level_ = sec_lvl_arg_.getValue();
            cout_param("secLevel", sec_level_);

            log_table_size_ = log_tbl_sz_arg_.getValue();
            cout_param("logTableSize", log_table_size_);

            split_count_ = split_cnt_arg_.getValue();
            cout_param("splitCount", split_count_);

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

            dbc_ = dbc_arg_.getValue();
            cout_param("dbc", dbc_);

            exfield_degree_ = exfld_degree_arg_.getValue();
            cout_param("exfieldDegree", exfield_degree_);

            db_file_ = db_file_arg_.getValue();
            cout_param("db", db_file_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);
        }

        bool use_labels() const { return use_labels_; }
        bool use_oprf() const { return oprf_; }
        unsigned item_bit_length() const { return item_bit_length_; }
        unsigned sec_level() const { return sec_level_; }
        int log_table_size() const { return log_table_size_; }
        int split_count() const { return split_count_; }
        int window_size() const { return window_size_; }
        int poly_modulus() const { return poly_modulus_; }
        const std::vector<u64>& coeff_modulus() const { return coeff_modulus_; }
        u64 plain_modulus() const { return plain_modulus_; }
        int dbc() const { return dbc_; }
        int exfield_degree() const { return exfield_degree_; }
        int net_port() const { return net_port_; }
        const std::string& db_file() const { return db_file_; }

    private:
        TCLAP::SwitchArg             labels_arg_          = TCLAP::SwitchArg("l", "useLabels", "Use labels", false);
        TCLAP::SwitchArg             oprf_arg_            = TCLAP::SwitchArg("o", "oprf", "Use OPRF", false);
        TCLAP::ValueArg<unsigned>    item_bit_length_arg_ = TCLAP::ValueArg<unsigned>("b", "itemBitLength", "Item bit length", false, 60, "unsigned");
        TCLAP::ValueArg<int>         net_port_arg_        = TCLAP::ValueArg<int>("", "port", "Network port to bind to", false, 1212, "int");
        TCLAP::ValueArg<std::string> db_file_arg_         = TCLAP::ValueArg<std::string>("", "db", "Path to the file containing the Sender database", true, "", "string");
        TCLAP::ValueArg<unsigned>    sec_lvl_arg_         = TCLAP::ValueArg<unsigned>("", "secLevel", "Security level", false, 40, "unsigned");
        TCLAP::ValueArg<int>         log_tbl_sz_arg_      = TCLAP::ValueArg<int>("", "logTableSize", "Table Size", false, 10, "int");
        TCLAP::ValueArg<int>         split_cnt_arg_       = TCLAP::ValueArg<int>("", "splitCount", "Split count", false, 128, "int");
        TCLAP::ValueArg<int>         wnd_sz_arg_          = TCLAP::ValueArg<int>("w", "windowSize", "Window size", false, 1, "int");
        TCLAP::ValueArg<int>         poly_mod_arg_        = TCLAP::ValueArg<int>("", "polyModulus", "Poly Modulus degree", false, 4096, "int");
        TCLAP::MultiArg<apsi::u64>   coeff_mod_arg_       = TCLAP::MultiArg<apsi::u64>("", "coeffModulus", "Coefficient Modulus", false, "u64");
        TCLAP::ValueArg<apsi::u64>   plain_mod_arg_       = TCLAP::ValueArg<apsi::u64>("", "plainModulus", "Plain Modulus", false, 0x13ff, "u64");
        TCLAP::ValueArg<int>         dbc_arg_             = TCLAP::ValueArg<int>("", "dbc", "Decomposition Bit Count", false, 30, "int");
        TCLAP::ValueArg<int>         exfld_degree_arg_    = TCLAP::ValueArg<int>("", "exfieldDegree", "exField degree", false, 8, "int");

        bool use_labels_;
        bool oprf_;
        unsigned item_bit_length_;
        unsigned sec_level_;
        int log_table_size_;
        int split_count_;
        int window_size_;
        int poly_modulus_;
        std::vector<u64> coeff_modulus_;
        u64 plain_modulus_;
        int dbc_;
        int exfield_degree_;
        int net_port_;
        std::string db_file_;
    };
}
