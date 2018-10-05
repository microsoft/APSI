#pragma once

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    class PSIParams;
    class CLP;

    namespace tools
    {
        /**
        Get a PSIParams object from a command line.
        */
        const PSIParams build_psi_params(
            const CLP& cmd,
            const apsi::u64 sender_set_size);
    }
}

