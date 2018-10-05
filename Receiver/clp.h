#pragma once

// STD
#include <string>

// Base
#include "base_clp.h"

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    /**
    * Command Line Processor for Receiver
    */
    class CLP : public BaseCLP
    {
    public:
        CLP(const std::string& desc, const std::string& version)
            : BaseCLP(desc, version)
        {
        }

        virtual void add_args()
        {
            add(net_addr_arg_);
            add(net_port_arg_);
            add(query_file_arg_);
        }

        virtual void get_args()
        {
            net_addr_ = net_addr_arg_.getValue();
            cout_param("address", net_addr_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);

            query_file_ = query_file_arg_.getValue();
            cout_param("query", query_file_);
        }

        const std::string& net_addr() const { return net_addr_; }
        int net_port() const { return net_port_; }
        const std::string& query_file() const { return query_file_; }

    private:
        TCLAP::ValueArg<std::string> net_addr_arg_ = TCLAP::ValueArg<std::string>("", "address", "Network address to connect to", false, "localhost", "string");
        TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>("", "port", "Network port to connect to", false, 1212, "int");
        TCLAP::ValueArg<std::string> query_file_arg_ = TCLAP::ValueArg<std::string>("q", "query", "Path to the file that contains query data", true, "", "string");

        std::string net_addr_;
        int net_port_;
        std::string query_file_;
    };
}
