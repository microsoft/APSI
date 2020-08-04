// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>

// APSI
#include "apsi/common/config.h"

namespace apsi
{
    constexpr static std::uint32_t apsi_version =
        (APSI_VERSION_PATCH << 20) + (APSI_VERSION_MINOR << 10) + APSI_VERSION_MAJOR;

    constexpr bool same_version(std::uint32_t version)
    {
        return version == apsi_version;
    }

    constexpr std::uint32_t get_major_version(std::uint32_t version)
    {
        return version & ((std::uint32_t(1) << 10) - 1);
    }

    constexpr std::uint32_t get_minor_version(std::uint32_t version)
    {
        return (version & ((std::uint32_t(1) << 20) - 1)) >> 10;
    }

    constexpr std::uint32_t get_patch_version(std::uint32_t version)
    {
        return version >> 20;
    }

    constexpr bool same_major_version(std::uint32_t version)
    {
        return get_major_version(version) == get_major_version(apsi_version);
    }

    constexpr bool same_minor_version(std::uint32_t version)
    {
        return get_minor_version(version) == get_minor_version(apsi_version);
    }

    constexpr bool same_patch_version(std::uint32_t version)
    {
        return get_patch_version(version) == get_patch_version(apsi_version);
    }
}
