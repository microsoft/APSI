// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/config.h"
#include "apsi/version.h"

namespace apsi {
    const uint32_t apsi_version =
        (APSI_VERSION_PATCH << 20) + (APSI_VERSION_MINOR << 10) + APSI_VERSION_MAJOR;

    bool same_version(uint32_t version)
    {
        return version == apsi_version;
    }

    uint32_t get_major_version(uint32_t version)
    {
        return version & ((uint32_t(1) << 10) - 1);
    }

    uint32_t get_minor_version(uint32_t version)
    {
        return (version & ((uint32_t(1) << 20) - 1)) >> 10;
    }

    uint32_t get_patch_version(uint32_t version)
    {
        return version >> 20;
    }

    bool same_major_version(uint32_t version)
    {
        return get_major_version(version) == get_major_version(apsi_version);
    }

    bool same_minor_version(uint32_t version)
    {
        return same_major_version(version) &&
               (get_minor_version(version) == get_minor_version(apsi_version));
    }

    bool same_patch_version(uint32_t version)
    {
        return same_minor_version(version) &&
               (get_patch_version(version) == get_patch_version(apsi_version));
    }
} // namespace apsi
