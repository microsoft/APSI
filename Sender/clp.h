#pragma once

#include "base_clp.h"

namespace apsi
{
    /**
    Command Line Processor for SenderExample
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

            db_file_ = db_file_arg_.getValue();
            cout_param("db", db_file_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);
        }

        bool use_labels() const { return use_labels_; }
        bool use_oprf() const { return oprf_; }
        unsigned item_bit_length() const { return item_bit_length_; }
        int net_port() const { return net_port_; }
        const std::string& db_file() const { return db_file_; }

    private:
        TCLAP::SwitchArg labels_arg_ = TCLAP::SwitchArg("l", "useLabels", "Use labels", false);
        TCLAP::SwitchArg oprf_arg_ = TCLAP::SwitchArg("o", "oprf", "Use OPRF", false);
        TCLAP::ValueArg<unsigned> item_bit_length_arg_ = TCLAP::ValueArg<unsigned>("b", "itemBitLength", "Item bit length", false, 60, "unsigned");
        TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>("", "port", "Network port to bind to", false, 1212, "int");
        TCLAP::ValueArg<std::string> db_file_arg_ = TCLAP::ValueArg<std::string>("", "db", "Path to the file containing the Sender database", true, "", "string");

        bool use_labels_;
        bool oprf_;
        unsigned item_bit_length_;
        int net_port_;
        std::string db_file_;
    };
}
