// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <exception>
#include <future>
#include <stdexcept>
#include <utility>
#include <vector>

// APSI
#include "apsi/util/thread_pool.h"

namespace apsi::util {
    /**
    Owns a set of tasks running on a ThreadPool and guarantees that none of them outlives this
    object.

    The problem this solves. A function that fans work out to a pool typically hands the tasks
    references to its own locals:

        vector<future<void>> futures(n);
        for (...) futures[i] = pool.enqueue([&]() { use(local_buffer); });
        for (auto &f : futures) { f.get(); }

    That last loop is unsafe. std::future::get() waits *and* rethrows, so the first failing task
    aborts the loop while tasks after it are still running. Futures produced by std::packaged_task
    -- which is what ThreadPool::enqueue returns -- do not wait when destroyed, so nothing stops
    or waits for those tasks. They keep running against local_buffer while the function unwinds
    and destroys it.

    TaskGroup makes that impossible: its destructor waits for every task it started. Whether the
    scope is left normally, by a task's exception, or by an exception thrown while tasks are
    still being added, no task can outlive the state it borrowed.

    Usage:

        TaskGroup tasks(pool);
        for (...) tasks.add([&]() { use(local_buffer); });
        tasks.join();

    Call join() to wait and observe task exceptions. Forgetting it is safe -- the destructor
    still waits -- you just lose the exception.

    IMPORTANT: declare the TaskGroup *after* everything its tasks capture by reference. Locals
    are destroyed in reverse order of declaration, so the group must be declared last in order to
    be destroyed first, while the state its tasks borrowed is still alive. No language feature
    can enforce this.

    Not thread-safe: add() and join() must be called from the thread that owns the group.

    Do not use a TaskGroup from inside a task that is itself running on the pool. join() blocks
    the worker it runs on while waiting for tasks queued to that same pool, so once as many such
    tasks are in flight as there are workers, none of the inner tasks can ever be scheduled and
    the pool deadlocks. Fan out at one level only, or do the nested work on the calling thread
    before the outer fan-out starts.
    */
    class TaskGroup {
    public:
        explicit TaskGroup(ThreadPool &pool) : pool_(pool)
        {}

        TaskGroup(const TaskGroup &) = delete;

        TaskGroup &operator=(const TaskGroup &) = delete;

        /**
        Waits for every task that has not already been waited for by join(). Exceptions are
        discarded: a destructor is implicitly noexcept, so letting one escape would call
        std::terminate, and on this path an exception is usually already in flight.
        */
        ~TaskGroup()
        {
            for (auto &f : futures_) {
                if (!f.valid()) {
                    continue;
                }

                try {
                    f.get();
                } catch (...) { // NOLINT(bugprone-empty-catch)
                    // See the comment above: nothing may escape a destructor.
                }
            }
        }

        /**
        Starts a task in the pool.

        The future is stored before the task is queued, not after. Writing
        futures.push_back(pool.enqueue(...)) instead would queue the task first and only then
        grow the container; if that growth threw, the returned future would be destroyed as a
        temporary while the task kept running, unreachable by join() or by the destructor -- the
        very abandonment this class exists to prevent. Growing first means a growth failure
        happens before anything is queued, and an enqueue failure leaves behind only an invalid
        future, which both join() and the destructor skip.
        */
        template <typename F, typename... Args>
        void add(F &&f, Args &&...args)
        {
            // Checked here rather than at join(), because by the time join() blocks the mistake
            // has already been made and whether it hangs is a matter of how many other workers
            // happen to be doing the same thing. Adding is the decision that makes the deadlock
            // possible, so that is what is reported.
            //
            // Unconditional rather than debug-only: no correct program trips this, the cost is a
            // pointer comparison against a thread-local, and the failure it replaces is a hang
            // with no diagnostic -- in a sender, a denial of service. An error that names the
            // problem is strictly better than a process that stops responding.
            if (pool_.is_worker_thread()) {
                throw std::logic_error(
                    "TaskGroup used from inside a task of the same thread pool; this deadlocks "
                    "once every worker is doing it");
            }

            futures_.emplace_back();
            futures_.back() = pool_.enqueue(std::forward<F>(f), std::forward<Args>(args)...);
        }

        /**
        Waits for every task, then rethrows the first exception thrown by any of them, ordered by
        when the task was added. Waiting for all of them before rethrowing is the point: returning
        while a task is still running is what makes the naive loop unsafe.

        Afterwards the group is empty, so calling join() again, or letting the destructor run, is
        a no-op.
        */
        void join()
        {
            std::exception_ptr first_exception;

            for (auto &f : futures_) {
                if (!f.valid()) {
                    continue;
                }

                try {
                    f.get();
                } catch (...) {
                    if (!first_exception) {
                        first_exception = std::current_exception();
                    }
                }
            }

            futures_.clear();

            if (first_exception) {
                std::rethrow_exception(first_exception);
            }
        }

        /**
        Reserves room for the given number of tasks. Purely an optimization.
        */
        void reserve(std::size_t task_count)
        {
            futures_.reserve(task_count);
        }

        /**
        The number of tasks added since construction or since the last join().
        */
        [[nodiscard]] std::size_t size() const noexcept
        {
            return futures_.size();
        }

    private:
        ThreadPool &pool_;

        std::vector<std::future<void>> futures_;
    };
} // namespace apsi::util
