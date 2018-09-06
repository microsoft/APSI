#pragma once

#include "base_clp.h"

namespace apsi
{
    class CLP : public BaseCLP
    {
    public:
        CLP(const std::string& desc)
            : BaseCLP(desc)
        {}

        virtual void add_args()
        {
            // Nothing needed
        }

        virtual void get_args()
        {
            // Nothing needed
        }
    };
}
