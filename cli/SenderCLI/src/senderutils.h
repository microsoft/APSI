// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

namespace apsi
{
    class PSIParams;
    class CLP;

    namespace util
    {
        /**
        Get a PSIParams object from a command line.
        */
        const PSIParams build_psi_params(
            const CLP& cmd,
            const std::uint64_t sender_set_size);
    } // namespace util
} // namespace apsi

