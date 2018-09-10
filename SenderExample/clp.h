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
            add(net_port_arg_);
        }

        virtual void get_args()
        {
            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);
        }

        int net_port() const { return net_port_; }

    private:
        TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>("", "port", "Network port to bind to", false, 1212, "int");

        int net_port_;
    };
}
