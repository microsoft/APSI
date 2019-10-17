// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>

// APSI
#include "apsi/apsidefines.h"

namespace apsi
{
    /**
    * Structure used to communicate results between Sender
    * and Receiver
    */
    struct ResultPackage
    {
        apsi::i64 split_idx;
        apsi::i64 batch_idx;
        std::string data;
        std::string label_data;

        // Calculate size of data in the structure
        apsi::u64 size() const
        {
            return sizeof(apsi::i64) * 2 +
                data.length() +
                label_data.length();
        }
    };
}
