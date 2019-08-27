// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>

// APSI
#include "apsi/apsidefines.h"
#include "apsi/result_package.h"
#include "apsi/psiparams.h"

namespace apsi
{
    namespace network
    {
        /**
        Response for Get Parameters request
        */
        struct SenderResponseGetParameters
        {
            apsi::PSIParams::PSIConfParams psiconf_params;
            apsi::PSIParams::TableParams   table_params;
            apsi::PSIParams::CuckooParams  cuckoo_params;
            apsi::PSIParams::SEALParams    seal_params;
            apsi::PSIParams::ExFieldParams exfield_params;
        };

        /**
        Response for Preprocess request
        */
        struct SenderResponsePreprocess
        {
            std::vector<apsi::u8> buffer;
        };

        /**
        Response for Query request
        */
        struct SenderResponseQuery
        {
            apsi::u64 package_count;
        };
    }
}
