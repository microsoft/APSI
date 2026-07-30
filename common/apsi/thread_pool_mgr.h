// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>

// APSI
#include "apsi/util/thread_pool.h"

namespace apsi {
    /**
    Reference-counting handle to a process-wide shared ThreadPool. The pool is created when the
    first ThreadPoolMgr is constructed and destroyed when the last one goes out of scope, so a
    process that is not currently running APSI work holds no worker threads.

    The reference counting is not merely an optimization. ThreadPool's workers are detached and
    may log on their way out, and ~ThreadPool blocks until they have all exited. A pool owned by
    a function-local static would instead be torn down during static destruction, racing the
    destruction of the logger it writes to -- these are separate translation units, so their
    relative destruction order is unspecified. Tying the pool's lifetime to a stack object
    destroys it at a deterministic point while the rest of the program is still alive.

    Instances are cheap; construct one in any scope that enqueues work, including nested scopes.
    All members are safe to call concurrently.
    */
    class ThreadPoolMgr {
    public:
        /**
        Take a reference on the shared thread pool, creating it if this is the first reference.
        */
        ThreadPoolMgr();

        /**
        Release the reference, destroying the shared thread pool if this was the last one.
        */
        ~ThreadPoolMgr();

        /**
        Get the shared thread pool. The reference stays valid for the lifetime of this instance.
        */
        [[nodiscard]]
        util::ThreadPool &thread_pool() const;

        /**
        Set the number of worker threads the shared pool runs, resizing it immediately if it
        currently exists. Zero requests the hardware default. The value is clamped into
        [ThreadPool::MinPoolSize(), ThreadPool::MaxPoolSize()].

        This also sets the fan-out width reported by GetThreadCount, so calling it after
        SetPoolWorkerCount discards that setting. Set this one first.
        */
        static void SetThreadCount(std::size_t threads);

        /**
        Set only the number of worker threads in the shared pool, leaving the fan-out width
        reported by GetThreadCount alone. This is what makes the two numbers diverge.

        Raising the worker count above the fan-out width is currently REQUIRED, not merely an
        optimization, whenever more than one APSI operation runs concurrently in a process.
        */
        static void SetPoolWorkerCount(std::size_t threads);

        /**
        Get the fan-out width: the number of tasks a single APSI operation splits itself into.
        Guaranteed to be at least one and never larger than the pool's cap. This is not
        necessarily the pool's worker count -- see SetPoolWorkerCount.
        */
        static std::size_t GetThreadCount();
    };
} // namespace apsi
