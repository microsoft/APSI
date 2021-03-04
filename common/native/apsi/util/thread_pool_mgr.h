// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>

// APSI
#include "thread_pool.h"

namespace apsi {
    namespace util {
        class ThreadPoolMgr {
        public:
            ThreadPoolMgr();
            ~ThreadPoolMgr();

            ThreadPool &thread_pool() const;

            static void set_thread_count(std::size_t threads);

        private:
            static std::size_t ref_count_;
        };
    } // namespace util
} // namespace apsi
