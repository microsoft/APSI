#pragma once

#include "utils.h"
#include "apsi/apsidefines.h"

namespace apsi
{
    namespace tools
    {
        block sysRandomSeed();
        bool not_equal(const apsi::block& lhs, const apsi::block& rhs);
    }
}
