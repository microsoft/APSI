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
        Not copyable or movable. A copy would not take a reference on the shared pool, yet its
        destructor would release one, so the reference count would drop while instances still
        hold the pool. Because the count is unsigned, the extra release underflows it, and every
        later ThreadPoolMgr then sees a nonzero count and never recreates the pool: the process
        is left permanently unable to run APSI work. There is no meaningful copy of a scope-bound
        reference anyway, so the operations are removed rather than defined.
        */
        ThreadPoolMgr(const ThreadPoolMgr &) = delete;

        ThreadPoolMgr(ThreadPoolMgr &&) = delete;

        ThreadPoolMgr &operator=(const ThreadPoolMgr &) = delete;

        ThreadPoolMgr &operator=(ThreadPoolMgr &&) = delete;

        /**
        Get the shared thread pool. The reference stays valid for the lifetime of this instance.
        */
        [[nodiscard]]
        util::ThreadPool &thread_pool() const;

        /**
        Set the number of worker threads the shared pool runs, resizing it immediately if it
        currently exists. Zero requests the hardware default. The value is clamped into
        [ThreadPool::MinPoolSize(), ThreadPool::MaxPoolSize()], and reduced further if the
        operating system refuses to create that many threads, so the counts reported afterwards
        may be lower than the value requested.

        This also sets the fan-out width reported by GetThreadCount, so calling it after
        SetPoolWorkerCount discards that setting. Set this one first.
        */
        static void SetThreadCount(std::size_t threads);

        /**
        Set only the number of worker threads in the shared pool, leaving the fan-out width
        reported by GetThreadCount alone. This is what makes the two numbers diverge.

        This is a tuning knob rather than a correctness requirement: APSI does not block a pool
        worker on the network, so concurrent operations sharing an undersized pool interleave
        rather than starve. Raising it above the fan-out width lets concurrent operations make
        progress at the same time instead of in sequence.

        Compare the result with GetPoolWorkerCount to see how many workers were actually
        obtained; a request the operating system could not satisfy is reduced, not refused.
        */
        static void SetPoolWorkerCount(std::size_t threads);

        /**
        Get the fan-out width: the number of tasks a single APSI operation splits itself into.
        Guaranteed to be at least one and never larger than the pool's cap. This is not
        necessarily the pool's worker count -- see SetPoolWorkerCount.
        */
        static std::size_t GetThreadCount();

        /**
        Get the number of worker threads the shared pool runs, which is what the pool actually
        obtained rather than what was last requested. If no pool currently exists this is the
        count the next one will be created with.
        */
        static std::size_t GetPoolWorkerCount();
    };
} // namespace apsi
