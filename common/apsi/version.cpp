// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSI
#include "apsi/config.h"
#include "apsi/version.h"

namespace apsi {
    const uint32_t apsi_version =
        (APSI_VERSION_PATCH << 20) + (APSI_VERSION_MINOR << 10) + APSI_VERSION_MAJOR;

    const uint32_t apsi_serialization_version = 1;

    bool same_serialization_version(uint32_t sv)
    {
        return sv == apsi_serialization_version;
    }
} // namespace apsi
