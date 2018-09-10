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
    * Command Line Processor for ReceiverExample
    */
    class CLP : public BaseCLP
    {
    public:
        CLP(const std::string& desc)
            : BaseCLP(desc)
        {
            std::vector<std::string> modes = { "local", "remote" };
            mode_constraint_ = std::make_unique<TCLAP::ValuesConstraint<std::string>>(modes);
            mode_arg_ = std::make_unique<TCLAP::ValueArg<std::string>>("m", "mode", "Operation mode", false, "local", mode_constraint_.get(), *this);
        }

        virtual void add_args()
        {
            add(rec_thr_arg_);
            add(net_addr_arg_);
            add(net_port_arg_);

            // No need to add mode_arg_. It was already added in the constructor.
        }

        virtual void get_args()
        {
            rec_threads_ = rec_thr_arg_.getValue();
            cout_param("recThreads", rec_threads_);

            mode_ = mode_arg_->getValue();
            cout_param("mode", mode_);

            net_addr_ = net_addr_arg_.getValue();
            cout_param("address", net_addr_);

            net_port_ = net_port_arg_.getValue();
            cout_param("port", net_port_);
        }

        int rec_threads() const { return rec_threads_; }
        const std::string& mode() const { return mode_; }
        const std::string& net_addr() const { return net_addr_; }
        int net_port() const { return net_port_; }

    private:
        TCLAP::ValueArg<std::string> net_addr_arg_ = TCLAP::ValueArg<std::string>("", "address", "Network address to connect to", false, "localhost", "string");
        TCLAP::ValueArg<int> net_port_arg_ = TCLAP::ValueArg<int>("", "port", "Network port to connect to", false, 1212, "int");
        TCLAP::ValueArg<int> rec_thr_arg_ = TCLAP::ValueArg<int>("r", "recThreads", "Receiver threads", false, 1, "int");
        std::unique_ptr<TCLAP::ValueArg<std::string>> mode_arg_;
        std::unique_ptr<TCLAP::ValuesConstraint<std::string>> mode_constraint_;

        int rec_threads_;
        std::string mode_;
        std::string net_addr_;
        int net_port_;
    };
}
