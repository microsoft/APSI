// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>

namespace apsi {
    extern const std::uint32_t apsi_version;

    extern const std::uint32_t apsi_serialization_version;

    bool same_serialization_version(std::uint32_t sv);
} // namespace apsi
