// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <memory>
#include <mutex>
#include <thread>

// APSI
#include "apsi/thread_pool_mgr.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace {
    mutex tp_mutex;

    // All four are guarded by tp_mutex.
    unique_ptr<ThreadPool> tp_ptr = nullptr;

    // Numeber of active references to the shared pool. The pool is created when this goes from 0 to
    // 1 and destroyed when it goes from 1 to 0. It is never decremented to zero while any ThreadPoolMgr
    // instance exists, so tp_ptr is never cleared while any instance can access it.
    std::size_t ref_count = 0;

    // Number of tasks a single APSI operation splits itself into. Zero means "not resolved yet";
    // it is never a resolved value, since resolve_thread_count returns at least
    // ThreadPool::MinPoolSize().
    std::size_t thread_count = 0;

    // Number of workers in the shared pool. Normally equal to thread_count; SetPoolWorkerCount
    // raises it above thread_count so that concurrent operations do not starve each other.
    std::size_t pool_worker_count = 0;

    /**
    Resolve a requested thread count to the number of workers the pool will actually run.

    A request of zero means "use the hardware default". std::thread::hardware_concurrency is
    permitted to return 0 when the value is not computable, so it cannot be used unguarded:
    every caller of thread_count below uses the result as a fan-out width, and a width of zero
    does not degrade to "run serially" but to "do no work at all". Requests above the pool's
    safety cap are clamped down for the same reason in reverse: a count larger than the pool
    will ever run makes callers allocate and enqueue work that has no worker to claim it.
    */
    size_t resolve_thread_count(size_t threads)
    {
        if (threads == 0) {
            threads = thread::hardware_concurrency();
        }
        return ThreadPool::ClampPoolSize(threads);
    }

    /**
    Read thread_count, resolving the hardware default on first use. Requires tp_mutex.
    */
    size_t thread_count_locked()
    {
        if (thread_count == 0) {
            thread_count = resolve_thread_count(0);
        }
        return thread_count;
    }

    /**
    Read pool_worker_count, resolving the hardware default on first use. Requires tp_mutex.
    */
    size_t pool_worker_count_locked()
    {
        if (pool_worker_count == 0) {
            pool_worker_count = resolve_thread_count(0);
        }
        return pool_worker_count;
    }
} // namespace

ThreadPoolMgr::ThreadPoolMgr()
{
    unique_lock<mutex> lock(tp_mutex);

    if (ref_count == 0) {
        tp_ptr = make_unique<ThreadPool>(pool_worker_count_locked());
    }

    ref_count++;
}

ThreadPoolMgr::~ThreadPoolMgr()
{
    unique_lock<mutex> lock(tp_mutex);

    ref_count--;
    if (ref_count == 0) {
        tp_ptr = nullptr;
    }
}

ThreadPool &ThreadPoolMgr::thread_pool() const
{
    // Read without tp_mutex, which is safe because this instance holds a reference: ref_count is
    // therefore nonzero, so no destructor can clear tp_ptr and no constructor can reassign it
    // (only the constructor that finds ref_count == 0 assigns). Locking here would put the mutex
    // on the per-task enqueue path for no benefit.
    if (!tp_ptr) {
        throw runtime_error("Thread pool is not available");
    }

    return *tp_ptr;
}

void ThreadPoolMgr::SetThreadCount(size_t threads)
{
    unique_lock<mutex> lock(tp_mutex);

    // Resize the pool before recording the new counts, so that a failure leaves both the pool and
    // the counts untouched and there is nothing to roll back. In practice set_pool_size does not
    // fail here: it only throws when the resize would leave the pool with no workers at all, and a
    // pool that already exists always has at least one (set_pool_size never targets fewer than
    // ThreadPool::MinPoolSize(), so a shrink always leaves one worker unclaimed).
    const size_t resolved = resolve_thread_count(threads);
    if (tp_ptr) {
        tp_ptr->set_pool_size(resolved);
    }

    thread_count = resolved;
    pool_worker_count = resolved;
}

void ThreadPoolMgr::SetPoolWorkerCount(size_t threads)
{
    unique_lock<mutex> lock(tp_mutex);

    // Ordered as in SetThreadCount: the fallible call comes first, the count is recorded only once
    // it has succeeded.
    const size_t resolved = resolve_thread_count(threads);
    if (tp_ptr) {
        tp_ptr->set_pool_size(resolved);
    }

    pool_worker_count = resolved;
}

size_t ThreadPoolMgr::GetThreadCount()
{
    unique_lock<mutex> lock(tp_mutex);

    return thread_count_locked();
}
