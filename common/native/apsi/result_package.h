// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>
#include "apsi/apsidefines.h"

namespace apsi
{
    /**
    * Structure used to communicate results between Sender
    * and Receiver
    */
    struct ResultPackage
    {
        i64 split_idx;
        i64 batch_idx;
        std::string data;
        std::string label_data;

        // Calculate size of data in the structure
        u64 size() const
        {
            return sizeof(i64) * 2 +
                data.length() +
                label_data.length();
        }
    }; // struct ResultPackage
} // namespace apsi
