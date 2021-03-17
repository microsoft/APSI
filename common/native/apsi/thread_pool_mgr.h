// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>

// APSI
#include "apsi/util/thread_pool.h"

namespace apsi {
    /**
    Manages lifetime of a static thread pool. While an instance of this class exists,
    a static thread pool will be shared among all instances.
    */
    class ThreadPoolMgr {
    public:
        /**
        Build an instance of ThreadPoolMgr
        */
        ThreadPoolMgr();

        /**
        Destructor for ThreadPoolMgr
        */
        ~ThreadPoolMgr();

        /**
        Get the thread pool managed by the thread pool manager
        */
        util::ThreadPool &thread_pool() const;

        /**
        Set the number of threads to be used by the thread pool
        */
        static void SetThreadCount(std::size_t threads);

        /**
        This method is to be used explicitly by tests.
        */
        static void SetPhysThreadCount(std::size_t threads);

        /**
        Get the number of threads used by the thread pool
        */
        static std::size_t GetThreadCount();

    private:
        /**
        Reference count to manage lifetime of the static thread pool
        */
        static std::size_t ref_count_;
    };
} // namespace apsi
