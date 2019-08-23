// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    class PSIParams;

    namespace tools
    {
        /**
        Get default parameters for PSI
        */
        const PSIParams default_psi_params(
            const apsi::u64 sender_set_size);
    }
}
