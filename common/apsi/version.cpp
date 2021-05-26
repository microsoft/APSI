// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/config.h"
#include "apsi/version.h"

namespace apsi {
    const uint32_t apsi_lib_version =
        (APSI_VERSION_PATCH << 20) + (APSI_VERSION_MINOR << 10) + APSI_VERSION_MAJOR;

    bool same_apsi_lib_version(uint32_t version)
    {
        return version == apsi_lib_version;
    }

    uint32_t get_apsi_lib_major_version(uint32_t version)
    {
        return version & ((uint32_t(1) << 10) - 1);
    }

    uint32_t get_apsi_lib_major_version()
    {
        return APSI_VERSION_MAJOR;
    }

    uint32_t get_apsi_lib_minor_version(uint32_t version)
    {
        return (version & ((uint32_t(1) << 20) - 1)) >> 10;
    }

    uint32_t get_apsi_lib_minor_version()
    {
        return APSI_VERSION_MINOR;
    }

    uint32_t get_apsi_lib_patch_version(uint32_t version)
    {
        return version >> 20;
    }

    uint32_t get_apsi_lib_patch_version()
    {
        return APSI_VERSION_PATCH;
    }

    bool same_apsi_lib_major_version(uint32_t version)
    {
        return get_apsi_lib_major_version(version) == get_apsi_lib_major_version();
    }

    bool same_apsi_lib_minor_version(uint32_t version)
    {
        return same_apsi_lib_major_version(version) &&
               (get_apsi_lib_minor_version(version) == get_apsi_lib_minor_version());
    }

    bool same_apsi_lib_patch_version(uint32_t version)
    {
        return same_apsi_lib_minor_version(version) &&
               (get_apsi_lib_patch_version(version) == get_apsi_lib_patch_version());
    }

    // The current protocol version is 1
    const uint32_t apsi_proto_version = 1;

    bool same_apsi_proto_version(uint32_t version)
    {
        return version == apsi_proto_version;
    }
} // namespace apsi
