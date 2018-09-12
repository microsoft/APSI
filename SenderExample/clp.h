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
        CLP(const std::string& desc)
            : BaseCLP(desc)
        {}

        virtual void add_args()
        {
            add(db_file_arg_);
            add(net_port_arg_);
        }

        virtual void get_args()
        {
            db_file_ = db_file_arg_.getValue();
            cout_param("db", db_file_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);
        }

        int net_port() const { return net_port_; }
        const std::string& db_file() const { return db_file_; }

    private:
        TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>("", "port", "Network port to bind to", false, 1212, "int");
        TCLAP::ValueArg<std::string> db_file_arg_ = TCLAP::ValueArg<std::string>("", "db", "Path to the file containing the Sender database", false, "", "string");

        int net_port_;
        std::string db_file_;
    };
}
