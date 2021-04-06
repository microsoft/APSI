// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>

namespace apsi {
    extern const std::uint32_t apsi_version;

    bool same_version(std::uint32_t version);

    std::uint32_t get_major_version(std::uint32_t version);

    std::uint32_t get_minor_version(std::uint32_t version);

    std::uint32_t get_patch_version(std::uint32_t version);

    bool same_major_version(std::uint32_t version);

    bool same_minor_version(std::uint32_t version);

    bool same_patch_version(std::uint32_t version);
} // namespace apsi
