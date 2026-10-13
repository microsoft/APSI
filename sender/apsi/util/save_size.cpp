// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstddef>
#include <string>

// APSI
#include "apsi/util/save_size.h"
#include "apsi/util/utils.h"

using namespace std;

namespace apsi::sender::util {
    namespace {
        thread_local size_t lowered_save_size_limit = apsi::util::max_buffer_size;
    } // namespace

    string refusal_reason(const SaveSizeBounds &bounds, size_t max_size)
    {
        string size = (bounds.lower > max_size) ? "at least " + to_string(bounds.lower)
                                                : "up to " + to_string(bounds.upper);
        return "takes " + size + " bytes, more than the " + to_string(max_size) +
               " bytes SenderDB::Load reads";
    }

    size_t save_size_limit() noexcept
    {
        return lowered_save_size_limit;
    }

    ScopedSaveSizeLimit::ScopedSaveSizeLimit(size_t limit) noexcept
        : previous_limit_(lowered_save_size_limit)
    {
        lowered_save_size_limit = min(limit, previous_limit_);
    }

    ScopedSaveSizeLimit::~ScopedSaveSizeLimit() noexcept
    {
        lowered_save_size_limit = previous_limit_;
    }
} // namespace apsi::sender::util
