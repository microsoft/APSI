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
        {}

        virtual void add_args()
        {
            add(rec_thr_arg_);
        }

        virtual void get_args()
        {
            rec_threads_ = rec_thr_arg_.getValue();
            cout_param("recThreads", rec_threads_);
        }

        int rec_threads() const { return rec_threads_; }

    private:
        TCLAP::ValueArg<int> rec_thr_arg_ = TCLAP::ValueArg<int>("r", "recThreads", "Receiver threads", false, 1, "int");

        int rec_threads_;
    };
}
