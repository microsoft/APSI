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
        necessarily the pool's worker count -- see SetPoolWorkerCount. While a
        ScopedParallelismLimit is in effect on the calling thread, the width reported to that
        thread is at most the limit.
        */
        static std::size_t GetThreadCount();

        /**
        Get the number of worker threads the shared pool runs, which is what the pool actually
        obtained rather than what was last requested. If no pool currently exists this is the
        count the next one will be created with.
        */
        static std::size_t GetPoolWorkerCount();
    };

    /**
    Limits the parallelism of the APSI operations that the calling thread begins while this
    object exists. Each fan-out such an operation makes runs at most max_tasks of its tasks at
    once on the shared thread pool. Operations take turns on the workers between tasks, never
    within one: when one of its tasks finishes, a fan-out's next task queues behind whatever other
    operations have queued on the pool meanwhile, but a task that has started runs to completion.
    ThreadPoolMgr::GetThreadCount reports at most max_tasks on this thread, so the fan-outs it
    sizes, the OPRF computations, PowersDag::parallel_apply and the loading of a query's
    ciphertexts in the sender::Query constructor, have at most max_tasks tasks, and
    receiver::Receiver::request_query starts at most max_tasks result threads, which are not on the
    pool. With a limit of one, a sender::Query loads the ciphertexts on the thread that creates it.
    The pool is neither resized nor reserved, so a limit above its worker count has no further
    effect. Operations begun on other threads are unaffected: concurrent operations with different
    limits share the pool without coordinating or serializing.

    The limit is per operation, not per SenderDB: two operations on one SenderDB begun on two
    threads each run under the limit of their own thread. To keep one SenderDB, or one server,
    within a single budget, run its operations one at a time.

    The limit belongs to the calling thread and does not follow work handed to other threads, so
    create it on the thread that runs the operation; for sender::ZMQSenderDispatcher, that is the
    thread that calls run.

    Limits nest. The smallest nonzero max_tasks among those alive on a thread is in effect, a
    max_tasks of zero adds no limit, and destroying a limit restores what was in effect before
    it. A limit must be destroyed on the thread that created it, in the reverse order of
    creation, as a local variable is; debug builds check this.
    */
    class ScopedParallelismLimit {
    public:
        /**
        Limit the operations this thread begins to max_tasks tasks at once in each fan-out, or,
        with zero, leave the limit as it is.
        */
        explicit ScopedParallelismLimit(std::size_t max_tasks) noexcept;

        /**
        Restore the limit that was in effect on this thread when this object was created.
        */
        ~ScopedParallelismLimit();

        ScopedParallelismLimit(const ScopedParallelismLimit &) = delete;

        ScopedParallelismLimit(ScopedParallelismLimit &&) = delete;

        ScopedParallelismLimit &operator=(const ScopedParallelismLimit &) = delete;

        ScopedParallelismLimit &operator=(ScopedParallelismLimit &&) = delete;

    private:
        // The limit, and the innermost ScopedParallelismLimit, on this thread before this one
        std::size_t outer_limit_;

        const ScopedParallelismLimit *outer_;
    };
} // namespace apsi
