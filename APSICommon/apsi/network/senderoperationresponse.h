// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
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
            PSIParams::PSIConfParams psiconf_params;
            PSIParams::TableParams   table_params;
            PSIParams::CuckooParams  cuckoo_params;
            PSIParams::SEALParams    seal_params;
            PSIParams::ExFieldParams exfield_params;
        }; // struct SenderResponseGetParameters

        /**
        Response for Preprocess request
        */
        struct SenderResponsePreprocess
        {
            std::vector<u8> buffer;
        }; // struct SenderResponsePreprocess

        /**
        Response for Query request
        */
        struct SenderResponseQuery
        {
            u64 package_count;
        }; // struct SenderResponseQuery
    } // namespace network
} // namespace apsi
