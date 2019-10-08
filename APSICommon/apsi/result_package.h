// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <string>

namespace apsi
{
    /**
    * Structure used to communicate results between Sender
    * and Receiver
    */
    struct ResultPackage
    {
        int split_idx;
        int batch_idx;
        std::string data;
        std::string label_data;

        // Calculate size of data in the structure
        size_t size() const
        {
            return sizeof(int) * 2 +
                data.length() +
                label_data.length();
        }
    };
}
