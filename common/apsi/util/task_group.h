// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/util/thread_pool.h"

namespace apsi::util {
    /**
    Returns the most tasks that a TaskGroup constructed on the calling thread runs at once: the
    smallest nonzero limit of the apsi::ScopedParallelismLimit objects alive on this thread, or
    zero if there is no limit. Defined in thread_pool_mgr.cpp, with the class that sets it.
    */
    [[nodiscard]] std::size_t parallelism_limit() noexcept;

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

    Not thread-safe: add() and join() must be called from the thread that owns the group, and
    that thread must also destroy it.

    Do not use a TaskGroup from inside a task that is itself running on the pool. join() blocks
    the worker it runs on while waiting for tasks queued to that same pool, so once as many such
    tasks are in flight as there are workers, none of the inner tasks can ever be scheduled and
    the pool deadlocks. Fan out at one level only, or do the nested work on the calling thread
    before the outer fan-out starts. On a worker of the group's pool, add() throws
    std::logic_error, and so does join() if the group has tasks, as when a task joins its own
    group; the destructor, which cannot throw, terminates the process rather than wait there.

    A TaskGroup constructed while an apsi::ScopedParallelismLimit is in effect on the calling
    thread runs at most that many of its tasks at once. It keeps its tasks in a queue of its own
    and admits at most that many runners to the pool. A runner runs one task and then, while
    tasks are waiting, queues itself again at the back of the pool's queue, so that concurrent
    operations take turns on the workers between tasks, rather than one holding them until all
    its tasks are done; a task that has started runs to completion. A task never runs on the
    thread that added it. Without a limit, every task is queued to the pool as soon as it is
    added.
    */
    class TaskGroup {
    public:
        explicit TaskGroup(ThreadPool &pool) : pool_(pool)
        {
            const std::size_t limit = parallelism_limit();
            if (limit) {
                limited_ = std::make_shared<Limited>(pool, limit);
            }
        }

        TaskGroup(const TaskGroup &) = delete;

        TaskGroup &operator=(const TaskGroup &) = delete;

        /**
        Waits for every task that has not already been waited for by join(), including those
        that have not started yet. Exceptions are discarded: a destructor is implicitly noexcept,
        so letting one escape would call std::terminate, and on this path an exception is usually
        already in flight.
        */
        ~TaskGroup()
        {
            // A wait here could deadlock, and the destructor can neither refuse by throwing, as
            // join() does, nor return while tasks still use what they borrowed. Say why before
            // terminating: a hang would leave no trace of the cause.
            if (waits_on_own_pool()) {
                try {
                    APSI_LOG_ERROR(
                        "TaskGroup destroyed with tasks outstanding inside a task of the same "
                        "thread pool; terminating");
                } catch (...) { // NOLINT(bugprone-empty-catch): logger may throw
                }
                std::terminate();
            }

            if (limited_) {
                std::unique_lock<std::mutex> lock(limited_->mutex);
                limited_->idle.wait(lock, [this] { return !limited_->unfinished; });
                return;
            }

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
        Starts a task in the pool, or, with a limit, queues it until a runner can take it.

        The future is stored before the task is queued, not after. Writing
        futures.push_back(pool.enqueue(...)) instead would queue the task first and only then
        grow the container; if that growth threw, the returned future would be destroyed as a
        temporary while the task kept running, unreachable by join() or by the destructor -- the
        very abandonment this class exists to prevent. Growing first means a growth failure
        happens before anything is queued, and an enqueue failure leaves behind only an invalid
        future, which both join() and the destructor skip. With a limit, a failure leaves the
        group exactly as it was.
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

            if (limited_) {
                // Bound as ThreadPool::enqueue binds, so that a task is called the same way
                // with a limit as without.
                // NOLINTNEXTLINE(modernize-avoid-bind)
                auto task = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
                submit(std::make_unique<BoundJob<decltype(task)>>(std::move(task)));
                return;
            }

            futures_.emplace_back();
            futures_.back() = pool_.enqueue(std::forward<F>(f), std::forward<Args>(args)...);
        }

        /**
        Waits for every task, then rethrows the first exception thrown by any of them, ordered by
        when the task was added. Waiting for all of them before rethrowing is the point: returning
        while a task is still running is what makes the naive loop unsafe.

        Afterwards the group is empty, so calling join() again, or letting the destructor run, is
        a no-op, and the group can be used again.
        */
        void join()
        {
            if (waits_on_own_pool()) {
                throw std::logic_error(
                    "TaskGroup joined from inside a task of the same thread pool; waiting there "
                    "can deadlock");
            }

            if (limited_) {
                join_limited();
                return;
            }

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
            if (!limited_) {
                futures_.reserve(task_count);
            }
        }

        /**
        The number of tasks added since construction or since the last join().
        */
        [[nodiscard]] std::size_t size() const noexcept
        {
            return limited_ ? limited_->results.size() : futures_.size();
        }

    private:
        // A task waiting in a group with a limit. Type-erased by hand, since std::function cannot
        // hold a move-only callable.
        class Job {
        public:
            Job() = default;

            Job(const Job &) = delete;

            Job &operator=(const Job &) = delete;

            virtual ~Job() = default;

            virtual void run() = 0;
        };

        template <typename Fn>
        class BoundJob final : public Job {
        public:
            explicit BoundJob(Fn &&fn) : fn_(std::move(fn))
            {}

            void run() override
            {
                fn_();
            }

        private:
            Fn fn_;
        };

        // What a group with a limit shares with its runners. Each runner holds it by shared_ptr,
        // so it stays alive until the last runner is done with it, even after the group is gone:
        // a runner still updates it after its last task has finished.
        struct Limited {
            Limited(ThreadPool &tp, std::size_t max_running) : pool(tp), limit(max_running)
            {}

            ThreadPool &pool;

            const std::size_t limit;

            std::mutex mutex;

            // Notified when the last unfinished task finishes
            std::condition_variable idle;

            // Tasks that have not started, oldest first, each with its result slot
            std::deque<std::pair<std::unique_ptr<Job>, std::exception_ptr *>> waiting;

            // A result slot for every task added since the last join(), in the order added. A
            // deque, so that each slot stays in place while more are added.
            std::deque<std::exception_ptr> results;

            // Runners admitted to the pool, whether queued there or running a task; at most limit
            std::size_t runners = 0;

            // Waiting tasks that no admitted runner is on its way to take
            std::size_t unclaimed = 0;

            // Tasks added and not yet finished
            std::size_t unfinished = 0;
        };

        // Whether waiting for the tasks here could block a worker that they need. A group can only
        // have tasks here if they were added on another thread, since add() refuses here.
        [[nodiscard]] bool waits_on_own_pool() const noexcept
        {
            return size() && pool_.is_worker_thread();
        }

        // join() for a group with a limit
        void join_limited()
        {
            std::exception_ptr first_exception;
            {
                std::unique_lock<std::mutex> lock(limited_->mutex);
                limited_->idle.wait(lock, [this] { return !limited_->unfinished; });

                for (auto &result : limited_->results) {
                    if (result) {
                        first_exception = std::move(result);
                        break;
                    }
                }

                limited_->results.clear();
            }

            if (first_exception) {
                std::rethrow_exception(first_exception);
            }
        }

        // Accepts a task into a group with a limit, or throws and leaves the group as it was.
        void submit(std::unique_ptr<Job> job)
        {
            std::lock_guard<std::mutex> lock(limited_->mutex);

            limited_->results.emplace_back();
            try {
                limited_->waiting.emplace_back(std::move(job), &limited_->results.back());

                // The runner is queued under the lock, so that if the pool refuses it, no other
                // runner can have taken the task meanwhile and the task can be withdrawn.
                if (limited_->runners < limited_->limit) {
                    try {
                        post_runner(limited_);
                    } catch (...) {
                        limited_->waiting.pop_back();
                        throw;
                    }
                    limited_->runners++;
                } else {
                    limited_->unclaimed++;
                }
            } catch (...) {
                limited_->results.pop_back();
                throw;
            }

            limited_->unfinished++;
        }

        // Queues a runner at the back of the pool's queue. Throws, having queued nothing, if the
        // pool does not take it. The future is not kept, as a runner reports through the state.
        static void post_runner(const std::shared_ptr<Limited> &limited)
        {
            limited->pool.enqueue([limited] { run_tasks(limited); });
        }

        // The body of a runner: runs one waiting task per turn on the pool, for as long as tasks
        // are waiting for it.
        static void run_tasks(const std::shared_ptr<Limited> &limited) noexcept
        {
            for (;;) {
                std::unique_ptr<Job> job;
                std::exception_ptr *result = nullptr;
                {
                    std::lock_guard<std::mutex> lock(limited->mutex);

                    // A runner is admitted, or stays, only for a task that no other runner will
                    // take, so one is waiting.
                    job = std::move(limited->waiting.front().first);
                    result = limited->waiting.front().second;
                    limited->waiting.pop_front();
                }

                std::exception_ptr error;
                try {
                    job->run();
                } catch (...) {
                    error = std::current_exception();
                }

                // Destroy the task, and whatever it captured, before reporting it finished: once
                // it has, the owner may return and leave the captured references dangling.
                job.reset();

                bool requeue = false;
                {
                    std::lock_guard<std::mutex> lock(limited->mutex);

                    *result = std::move(error);

                    // Decided under the lock that add() takes, so that no task is ever left
                    // without a runner: either this runner sees the new task, or add() sees that
                    // the runner has gone and admits another.
                    if (limited->unclaimed) {
                        limited->unclaimed--;
                        requeue = true;
                    } else {
                        limited->runners--;
                    }

                    if (!--limited->unfinished) {
                        limited->idle.notify_all();
                    }
                }

                if (!requeue) {
                    return;
                }

                // Go to the back of the pool's queue rather than straight on to the next task, so
                // that other operations sharing the pool get their turns in between.
                try {
                    post_runner(limited);
                    return;
                } catch (...) { // NOLINT(bugprone-empty-catch)
                    // The task this runner took would otherwise never run, and the group's owner
                    // would wait for it forever. Run it on this turn instead.
                }
            }
        }

        ThreadPool &pool_;

        std::vector<std::future<void>> futures_;

        // State shared with the runners, when there is a limit
        std::shared_ptr<Limited> limited_;
    };
} // namespace apsi::util
