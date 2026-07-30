// -*- C++ -*-
// Copyright (c) 2012-2015 Jakob Progsch
//
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
//    1. The origin of this software must not be misrepresented; you must not
//    claim that you wrote the original software. If you use this software
//    in a product, an acknowledgment in the product documentation would be
//    appreciated but is not required.
//
//    2. Altered source versions must be plainly marked as such, and must not be
//    misrepresented as being the original software.
//
//    3. This notice may not be removed or altered from any source
//    distribution.
//
// Modified for log4cplus, copyright (c) 2014-2015 Václav Zeman.
//
// -----------------------------------------------------------------------------
// Altered source version, plainly marked as such per condition (2) above.
// Extensively rewritten and simplified for APSI:
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
//
// The public interface (enqueue, wait_until_empty, wait_until_nothing_in_flight,
// set_pool_size) and the in-flight-tracking design derive from the works above.
// The worker lifecycle (detached workers tracked by count), pool resizing
// (pending-exit tokens), synchronization (a single mutex with dedicated
// condition variables), and task exception handling have been reimplemented.
// -----------------------------------------------------------------------------

#pragma once

// STD
#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>

// APSI
#include "apsi/log.h"

namespace apsi::util {

    /**
    Thread pool used by APSI internals. Workers are interchangeable: they are spawned with
    std::thread::detach so the pool never owns thread handles, only an active-worker count.
    Resizing is done by raising or lowering a pending-exit counter that any waiting worker can
    claim. The task queue is unbounded; tasks that throw are caught and logged so a single bad
    task cannot tear down a worker. Destruction sets a stop flag, drains pending tasks, and
    waits for the active count to reach zero before returning.
    */
    class ThreadPool {
    public:
        explicit ThreadPool(std::size_t threads)
        {
            set_pool_size(threads);
        }

        ThreadPool(const ThreadPool &) = delete;
        ThreadPool &operator=(const ThreadPool &) = delete;
        ThreadPool(ThreadPool &&) = delete;
        ThreadPool &operator=(ThreadPool &&) = delete;

        ~ThreadPool()
        {
            std::unique_lock<std::mutex> lock(mutex_);
            stop_ = true;
            queue_cv_.notify_all();
            workers_empty_cv_.wait(lock, [this] { return active_workers_ == 0; });
        }

        /**
        Schedule a callable to run on a worker thread. Returns a std::future to retrieve the
        callable's return value (or rethrow its exception). Throws std::runtime_error if called
        after the pool has been signaled to stop.
        */
        template <typename F, typename... Args>
        auto enqueue(F &&f, Args &&...args) -> std::future<std::invoke_result_t<F, Args...>>
        {
            using return_type = std::invoke_result_t<F, Args...>;

            // std::bind is deliberate here. Forwarding the argument pack into a lambda capture
            // needs C++20 pack-capture ([...args = std::forward<Args>(args)]); in C++17 a pack
            // cannot be expanded in an init-capture. bind decay-copies its arguments, so the
            // documented way to hand move-only state to a task is to capture it in the callable
            // itself rather than pass it as a trailing argument (see the MoveOnlyTaskArgs test).
            auto task = std::make_shared<std::packaged_task<return_type()>>(
                // NOLINTNEXTLINE(modernize-avoid-bind)
                std::bind(std::forward<F>(f), std::forward<Args>(args)...));
            std::future<return_type> res = task->get_future();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_) {
                    throw std::runtime_error("enqueue on stopped ThreadPool");
                }
                tasks_.emplace([task] { (*task)(); });
                in_flight_++;
            }
            queue_cv_.notify_one();

            return res;
        }

        /**
        Block until the task queue is empty. Tasks may still be running after this returns;
        call wait_until_nothing_in_flight to also wait for in-progress tasks.
        */
        void wait_until_empty()
        {
            std::unique_lock<std::mutex> lock(mutex_);
            empty_cv_.wait(lock, [this] { return tasks_.empty(); });
        }

        /**
        Block until every enqueued task has finished executing.
        */
        void wait_until_nothing_in_flight()
        {
            std::unique_lock<std::mutex> lock(mutex_);
            in_flight_cv_.wait(lock, [this] { return in_flight_ == 0; });
        }

        /**
        Smallest number of workers a pool may have. A pool of zero workers would accept tasks
        and never run them.
        */
        static constexpr std::size_t MinPoolSize()
        {
            return 1;
        }

        /**
        Largest number of workers a pool may have: 16 times the number of hardware threads.
        This is far more than any APSI workload benefits from, and exists only so that a
        nonsensical thread count -- a typo in a config file, say -- cannot make the pool keep
        starting threads until the operating system refuses to create more. Note that
        std::thread::hardware_concurrency may return 0 when it cannot determine the hardware
        thread count, hence the floor of 1.
        */
        static std::size_t MaxPoolSize()
        {
            return static_cast<std::size_t>((std::max)(1U, std::thread::hardware_concurrency())) *
                   16;
        }

        /**
        Clamp a requested worker count into [MinPoolSize(), MaxPoolSize()]. Callers that
        report a pool size to others should clamp with this so that the number they publish
        matches the number of workers the pool will actually run.
        */
        static std::size_t ClampPoolSize(std::size_t size)
        {
            if (size < MinPoolSize()) {
                return MinPoolSize();
            }
            const std::size_t max_size = MaxPoolSize();
            if (size > max_size) {
                APSI_LOG_WARNING(
                    "Requested thread pool size " << size << " exceeds the maximum of " << max_size
                                                  << "; using " << max_size << " threads instead");
                return max_size;
            }
            return size;
        }

        /**
        Resize the pool to new_size workers. new_size is clamped into[MinPoolSize(), MaxPoolSize()].
        Growing first cancels any currently pending exits, then spawns the remaining shortfall as
        new detached threads. Shrinking raises pending_exits_ by the appropriate delta and wakes the
        waiters; whichever workers claim the tokens first will exit. After this call returns the
        logical pool size is new_size, but the actual active count converges asynchronously as
        workers wake.

        If the operating system refuses to create a thread partway through a grow, the pool keeps
        the workers it managed to start and logs a warning rather than propagating the failure:
        running with fewer workers is slower but correct. The exception is only allowed to escape
        when the pool has no workers at all, since such a pool would accept tasks and never run
        them. See the comment in the spawn loop for why this distinction matters.
        */
        void set_pool_size(std::size_t new_size)
        {
            new_size = ClampPoolSize(new_size);

            std::size_t spawned = 0;
            std::size_t wanted = 0;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_) {
                    return;
                }

                const std::size_t current_target = active_workers_ - pending_exits_;
                if (new_size == current_target) {
                    return;
                }

                if (new_size > current_target) {
                    std::size_t delta = new_size - current_target;
                    const std::size_t cancel = (std::min)(pending_exits_, delta);
                    pending_exits_ -= cancel;
                    delta -= cancel;
                    wanted = delta;
                    for (; spawned < delta; spawned++) {
                        try {
                            std::thread worker([this] { worker_loop(); });
                            worker.detach();
                        } catch (...) {
                            // Thread creation failed. Every worker started above this point is
                            // detached and holds a pointer to this pool, so letting the exception
                            // escape a constructor call would destroy the pool while those workers
                            // are still running against it. Keep what we have instead. When no
                            // worker exists at all there is nothing to strand, and a pool with no
                            // workers would silently swallow every task, so that case must fail.
                            if (active_workers_ == 0) {
                                throw;
                            }
                            break;
                        }
                        active_workers_++;
                    }
                } else {
                    pending_exits_ += (current_target - new_size);
                    queue_cv_.notify_all();
                }
            }

            if (spawned < wanted) {
                APSI_LOG_WARNING(
                    "The operating system refused to create more threads; the thread pool started "
                    << spawned << " of the " << wanted << " additional workers it requested");
            }
        }

        /**
        Return the current logical size of the pool: the number of workers the pool is converging
        toward, i.e. the value most recently requested via the constructor or set_pool_size (after
        the zero-to-one and safety-cap clamping). Growth takes effect synchronously -- the new
        workers are spawned before set_pool_size returns -- so a grow is reflected at once. A shrink
        is asynchronous: the excess workers keep running until they wake and claim a pending-exit
        token, but this method reports the post-shrink target immediately rather than the
        temporarily larger live-worker count. For a live pool the result is always at least one.
        */
        [[nodiscard]]
        std::size_t pool_size() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // active_workers_ >= pending_exits_ holds for any live pool (each worker that claims an
            // exit token decrements both counters in the same critical section), so this is the
            // logical target. Guard the subtraction anyway so a caller racing with teardown --
            // where workers exit without clearing pending_exits_ -- can never observe an underflow.
            return active_workers_ > pending_exits_ ? active_workers_ - pending_exits_ : 0;
        }

    private:
        void worker_loop()
        {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    queue_cv_.wait(
                        lock, [this] { return stop_ || !tasks_.empty() || pending_exits_ > 0; });

                    if (stop_ && tasks_.empty()) {
                        on_worker_exit_locked();
                        return;
                    }

                    if (pending_exits_ > 0 && !stop_) {
                        pending_exits_--;
                        on_worker_exit_locked();
                        return;
                    }

                    task = std::move(tasks_.front());
                    tasks_.pop();
                    if (tasks_.empty()) {
                        empty_cv_.notify_all();
                    }
                }

                try {
                    task();
                } catch (const std::exception &ex) {
                    // Logging itself can throw (allocator failure, logger torn down during
                    // shutdown). Detached threads must never let an exception escape or the
                    // process terminates.
                    try {
                        APSI_LOG_ERROR("Unhandled exception in thread pool task: " << ex.what());
                    } catch (...) { // NOLINT(bugprone-empty-catch): logger may throw
                    }
                } catch (...) {
                    try {
                        APSI_LOG_ERROR("Unhandled non-standard exception in thread pool task");
                    } catch (...) { // NOLINT(bugprone-empty-catch): logger may throw
                    }
                }

                bool notify_drained = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    notify_drained = (--in_flight_ == 0);
                }
                if (notify_drained) {
                    in_flight_cv_.notify_all();
                }
            }
        }

        // Caller must hold mutex_.
        void on_worker_exit_locked()
        {
            if (--active_workers_ == 0) {
                workers_empty_cv_.notify_all();
            }
        }

        std::queue<std::function<void()>> tasks_;
        std::size_t active_workers_ = 0;
        std::size_t pending_exits_ = 0;
        std::size_t in_flight_ = 0;
        bool stop_ = false;

        mutable std::mutex mutex_;
        std::condition_variable queue_cv_;
        std::condition_variable empty_cv_;
        std::condition_variable in_flight_cv_;
        std::condition_variable workers_empty_cv_;
    };

} // namespace apsi::util
