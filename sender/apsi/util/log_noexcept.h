// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// This header is internal to APSI and is not installed.

namespace apsi::sender::util {
    /**
    Calls log, which logs a message, and drops the message if logging throws. Logging allocates and
    calls the user's handler, either of which can throw. An update to a SenderDB that threw once it
    had begun to change the BinBundles would leave them out of step with the set of items, or with
    stale caches, so from its first change until its caches are regenerated, the update logs
    through this, unless it is about to throw anyway.
    */
    template <typename LogFunc>
    void log_noexcept(const LogFunc &log) noexcept
    {
        try {
            log();
        } catch (...) { // NOLINT(bugprone-empty-catch): logger may throw
        }
    }
} // namespace apsi::sender::util
