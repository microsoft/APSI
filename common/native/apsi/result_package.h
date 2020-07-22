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
        std::size_t bin_bundle_index;
        std::string data;
        std::string label_data;

        // Calculate size of data in the structure
        std::uint64_t size() const
        {
            return sizeof(std::size_t) + data.length() + label_data.length();
        }
    }; // struct ResultPackage
} // namespace apsi
