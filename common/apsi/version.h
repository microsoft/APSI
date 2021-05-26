// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>

namespace apsi {
    extern const std::uint32_t apsi_lib_version;

    bool same_apsi_lib_version(std::uint32_t version);

    std::uint32_t get_apsi_lib_major_version(std::uint32_t version);

    std::uint32_t get_apsi_lib_major_version();

    std::uint32_t get_apsi_lib_minor_version(std::uint32_t version);

    std::uint32_t get_apsi_lib_minor_version();

    std::uint32_t get_apsi_lib_patch_version(std::uint32_t version);

    std::uint32_t get_apsi_lib_patch_version();

    bool same_apsi_lib_major_version(std::uint32_t version);

    bool same_apsi_lib_minor_version(std::uint32_t version);

    bool same_apsi_lib_patch_version(std::uint32_t version);

    extern const std::uint32_t apsi_proto_version;

    bool same_apsi_proto_version(std::uint32_t version);
} // namespace apsi
