// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <vector>
#include <cstdint>

// APSI
#include "apsi/psiparams.h"
#include "apsi/result_package.h"

// SEAL
#include <seal/util/defines.h>

namespace apsi
{
    namespace network
    {
        /**
        Sender's response to a parameter request.
        */
        struct SenderResponseParms
        {
            PSIParams::PSIConfParams psiconf_params;
            PSIParams::TableParams table_params;
            PSIParams::CuckooParams cuckoo_params;
            PSIParams::SEALParams seal_params;
        }; // struct SenderResponseParms

        /**
        Sender's response to an OPRF query. 
        */
        struct SenderResponseOPRF
        {
            std::vector<seal::SEAL_BYTE> data;
        }; // struct SenderResponseOPRF

        /**
        Sender's response to a PSI or labeled PSI query. We only return the number of packages that
        the receiver should be expected to receive.
        */
        struct SenderResponseQuery
        {
            std::uint64_t package_count;
        }; // struct SenderResponseQuery
    }      // namespace network
} // namespace apsi
