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
        std::int64_t split_idx;
        std::int64_t batch_idx;
        std::string data;
        std::string label_data;

        // Calculate size of data in the structure
        std::uint64_t size() const
        {
            return sizeof(std::int64_t) * 2 + data.length() + label_data.length();
        }
    }; // struct ResultPackage
} // namespace apsi
