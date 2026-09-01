// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <future>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

// APSI
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/thread_pool.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace std::chrono_literals;
using namespace apsi;
using namespace apsi::util;

namespace APSITests {
    namespace {
        // Spin with a hard deadline so tests fail loudly instead of hanging the suite.
        // Returns true if `pred` became true within `deadline`, false otherwise.
        template <typename Pred>
        bool spin_until(Pred pred, chrono::milliseconds deadline = 5000ms)
        {
            auto end = chrono::steady_clock::now() + deadline;
            while (!pred()) {
                if (chrono::steady_clock::now() > end) {
                    return false;
                }
                this_thread::sleep_for(1ms);
            }
            return true;
        }

        // A barrier-task: increments `running` on entry, then blocks on a shared future. Tests
        // use this to pin workers in a known state and observe how many run in parallel. The state
        // is private behind a constructor so this functor-with-behavior does not trip
        // misc-non-private-member-variables-in-classes; brace-init at the call sites is unaffected.
        class BarrierTask {
        public:
            BarrierTask(atomic<int> *running, shared_future<void> release)
                : running_(running), release_(std::move(release))
            {}

            void operator()() const
            {
                running_->fetch_add(1, memory_order_acq_rel);
                release_.wait();
            }

        private:
            atomic<int> *running_;
            shared_future<void> release_;
        };
    } // namespace

    TEST(ThreadPoolTests, BasicEnqueueAndResult)
    {
        ThreadPool pool(2);
        auto fut = pool.enqueue([] { return 42; });
        ASSERT_EQ(42, fut.get());
    }

    TEST(ThreadPoolTests, MultipleTasksAllExecute)
    {
        ThreadPool pool(4);
        constexpr size_t N = 200;
        vector<future<size_t>> results;
        results.reserve(N);
        for (size_t i = 0; i < N; i++) {
            results.push_back(pool.enqueue([i] { return i * i; }));
        }
        for (size_t i = 0; i < N; i++) {
            ASSERT_EQ(i * i, results[i].get());
        }
    }

    TEST(ThreadPoolTests, TasksRunOnDistinctThreads)
    {
        ThreadPool pool(4);
        promise<void> release;
        shared_future<void> sf = release.get_future().share();
        atomic<int> running(0);

        // Pin all 4 workers.
        vector<future<thread::id>> ids;
        ids.reserve(4);
        for (int i = 0; i < 4; i++) {
            ids.push_back(pool.enqueue([&running, sf] {
                running.fetch_add(1, memory_order_acq_rel);
                sf.wait();
                return this_thread::get_id();
            }));
        }
        ASSERT_TRUE(spin_until([&] { return running.load() == 4; }))
            << "expected 4 workers running concurrently";

        release.set_value();
        set<thread::id> distinct;
        for (auto &f : ids) {
            distinct.insert(f.get());
        }
        ASSERT_EQ(size_t(4), distinct.size());
    }

    TEST(ThreadPoolTests, ZeroSizeClampsToOne)
    {
        ThreadPool pool(0);
        // A requested size of zero must clamp up to exactly one worker -- not zero, and not the
        // default hardware-derived size.
        ASSERT_EQ(size_t(1), pool.pool_size());
        auto fut = pool.enqueue([] { return 7; });
        ASSERT_EQ(7, fut.get());
    }

    TEST(ThreadPoolTests, WaitUntilEmptyReturnsAfterQueueDrained)
    {
        ThreadPool pool(2);
        atomic<int> done(0);
        for (int i = 0; i < 50; i++) {
            pool.enqueue([&done] {
                this_thread::sleep_for(1ms);
                done.fetch_add(1, memory_order_acq_rel);
            });
        }
        pool.wait_until_empty();
        // wait_until_empty may return before all in-flight tasks finish; just assert no tasks
        // are queued by following up with wait_until_nothing_in_flight.
        pool.wait_until_nothing_in_flight();
        ASSERT_EQ(50, done.load());
    }

    TEST(ThreadPoolTests, WaitUntilNothingInFlightWaitsForRunningTask)
    {
        ThreadPool pool(2);
        atomic<bool> task_done(false);
        pool.enqueue([&task_done] {
            this_thread::sleep_for(20ms);
            task_done.store(true, memory_order_release);
        });
        pool.wait_until_nothing_in_flight();
        ASSERT_TRUE(task_done.load(memory_order_acquire));
    }

    TEST(ThreadPoolTests, TaskExceptionDoesNotKillWorker)
    {
        ThreadPool pool(1); // single worker so the same worker survives both tasks
        auto bad = pool.enqueue([] { throw runtime_error("boom"); });
        ASSERT_THROW(bad.get(), runtime_error);

        auto good = pool.enqueue([] { return 99; });
        ASSERT_EQ(99, good.get());
    }

    TEST(ThreadPoolTests, GrowAllowsMoreParallelism)
    {
        ThreadPool pool(2);
        promise<void> release;
        shared_future<void> sf = release.get_future().share();
        atomic<int> running(0);

        // Pin both starting workers.
        BarrierTask barrier{ &running, sf };
        pool.enqueue(barrier);
        pool.enqueue(barrier);
        ASSERT_TRUE(spin_until([&] { return running.load() == 2; }));
        ASSERT_EQ(size_t(2), pool.pool_size());

        // Grow. New tasks should run on freshly-spawned workers because the original two are
        // still pinned.
        pool.set_pool_size(4);
        ASSERT_EQ(size_t(4), pool.pool_size());
        pool.enqueue(barrier);
        pool.enqueue(barrier);
        ASSERT_TRUE(spin_until([&] { return running.load() == 4; }))
            << "set_pool_size(4) should have spawned 2 new workers";

        release.set_value();
        pool.wait_until_nothing_in_flight();
    }

    TEST(ThreadPoolTests, ShrinkReducesParallelism)
    {
        ThreadPool pool(4);

        // Drive the pool through one batch to confirm it can run 4 concurrently first.
        {
            promise<void> rel;
            shared_future<void> sf = rel.get_future().share();
            atomic<int> running(0);
            BarrierTask barrier{ &running, sf };
            for (int i = 0; i < 4; i++) {
                pool.enqueue(barrier);
            }
            ASSERT_TRUE(spin_until([&] { return running.load() == 4; }));
            rel.set_value();
            pool.wait_until_nothing_in_flight();
        }

        // Shrink to 2 and let the excess workers exit before measuring.
        pool.set_pool_size(2);
        // The logical target drops immediately even though the excess workers exit asynchronously.
        ASSERT_EQ(size_t(2), pool.pool_size());
        // The shrink is asynchronous; nudge it by enqueueing a single fast task and then waiting
        // for the pool to drain. Workers will wake on this task plus the pending exits.
        pool.enqueue([] {}).get();

        // Now pin 2 workers; a 3rd task must NOT start until one of them is released.
        promise<void> rel;
        shared_future<void> sf = rel.get_future().share();
        atomic<int> running(0);
        BarrierTask barrier{ &running, sf };
        pool.enqueue(barrier);
        pool.enqueue(barrier);
        ASSERT_TRUE(spin_until([&] { return running.load() == 2; }));

        atomic<bool> third_started(false);
        auto third =
            pool.enqueue([&third_started] { third_started.store(true, memory_order_release); });

        // Give the third task time to run if there were a 3rd worker. After 100ms with no third
        // worker, it must still be queued.
        this_thread::sleep_for(100ms);
        ASSERT_FALSE(third_started.load(memory_order_acquire))
            << "third task started while two workers are pinned -> shrink did not take effect";

        rel.set_value();
        third.get();
        pool.wait_until_nothing_in_flight();
    }

    TEST(ThreadPoolTests, GrowAfterShrinkCancelsPendingExits)
    {
        // This exercises the cancel-pending-exits branch in set_pool_size: shrink to 1, then
        // before the excess workers have had a chance to claim their exit tokens, grow back to 4.
        // The pending tokens must be cancelled rather than fire stale, otherwise we'd end up with
        // fewer than 4 workers.
        ThreadPool pool(4);
        ASSERT_EQ(size_t(4), pool.pool_size());

        // Don't enqueue anything; workers are idle, parked on queue_cv_. Shrink + grow back-to-back
        // while they sleep.
        pool.set_pool_size(1);
        // The logical target is exact and synchronous even while the excess workers are still
        // alive, so we can assert the shrink landed before growing back.
        ASSERT_EQ(size_t(1), pool.pool_size());
        pool.set_pool_size(4);
        // Growing back must cancel the three pending-exit tokens rather than let them fire, so the
        // target returns to exactly 4. This is the branch the test is named for; assert it directly
        // instead of only inferring it from the parallelism check below.
        ASSERT_EQ(size_t(4), pool.pool_size());

        promise<void> rel;
        shared_future<void> sf = rel.get_future().share();
        atomic<int> running(0);
        BarrierTask barrier{ &running, sf };
        for (int i = 0; i < 4; i++) {
            pool.enqueue(barrier);
        }
        ASSERT_TRUE(spin_until([&] { return running.load() == 4; }))
            << "shrink-then-grow lost workers; cancel-pending-exits did not work";

        rel.set_value();
        pool.wait_until_nothing_in_flight();
    }

    TEST(ThreadPoolTests, SetPoolSizeSameValueIsNoOp)
    {
        ThreadPool pool(3);
        ASSERT_EQ(size_t(3), pool.pool_size());
        // Invoking set_pool_size with the current value should not perturb anything.
        pool.set_pool_size(3);
        pool.set_pool_size(3);
        ASSERT_EQ(size_t(3), pool.pool_size());
        // Pool still functions.
        ASSERT_EQ(7, pool.enqueue([] { return 7; }).get());
    }

    TEST(ThreadPoolTests, PoolSizeReportsLogicalTarget)
    {
        // pool_size() reports the logical target: exact and synchronous for construction and for
        // growth, and updated immediately on shrink even though the excess workers exit lazily.
        // The active-minus-pending difference is invariant under worker exit (each exit decrements
        // both counters together), so every assertion below is deterministic without any waiting.
        ThreadPool pool(3);
        ASSERT_EQ(size_t(3), pool.pool_size());

        // Grow: new workers are spawned before set_pool_size returns, so this is exact at once.
        pool.set_pool_size(5);
        ASSERT_EQ(size_t(5), pool.pool_size());

        // Shrink: the target drops immediately; the three excess workers exit asynchronously later.
        // We assert the reported size without waiting for them, which is the whole point.
        pool.set_pool_size(2);
        ASSERT_EQ(size_t(2), pool.pool_size());

        // Zero clamps to one.
        pool.set_pool_size(0);
        ASSERT_EQ(size_t(1), pool.pool_size());

        // Still functional after all the churn.
        ASSERT_EQ(11, pool.enqueue([] { return 11; }).get());
    }

    TEST(ThreadPoolTests, ManyResizeCyclesNoHangOrLeak)
    {
        ThreadPool pool(2);
        for (size_t cycle = 0; cycle < 50; cycle++) {
            pool.set_pool_size(1 + (cycle % 6));
            ASSERT_EQ(cycle, pool.enqueue([cycle] { return cycle; }).get());
        }
        pool.wait_until_nothing_in_flight();
    }

    TEST(ThreadPoolTests, ConcurrentEnqueueAndResizeStress)
    {
        ThreadPool pool(2);
        constexpr int producer_count = 4;
        static constexpr int tasks_per_producer = 250;
        atomic<int> done(0);

        vector<thread> producers;
        producers.reserve(producer_count);
        for (int p = 0; p < producer_count; p++) {
            producers.emplace_back([&pool, &done] {
                for (int i = 0; i < tasks_per_producer; i++) {
                    pool.enqueue([&done] { done.fetch_add(1, memory_order_acq_rel); });
                }
            });
        }

        // Resize the pool aggressively while producers run.
        thread resizer([&pool] {
            for (size_t i = 0; i < 200; i++) {
                pool.set_pool_size(1 + (i % 5));
                this_thread::sleep_for(100us);
            }
        });

        for (auto &t : producers) {
            t.join();
        }
        resizer.join();

        pool.wait_until_nothing_in_flight();
        ASSERT_EQ(producer_count * tasks_per_producer, done.load());
    }

    TEST(ThreadPoolTests, DestructorWithStaleShrinkPendingExits)
    {
        // A pool with a pending shrink is destroyed before the workers have had a chance to
        // claim their pending_exits_ tokens. The stop branch must still drain the workers and
        // the destructor must return cleanly. Repeat with random delays to shake out timing.
        for (int trial = 0; trial < 20; trial++) {
            ThreadPool pool(4);
            pool.set_pool_size(1); // pending_exits_ = 3, workers haven't necessarily woken yet
            // Don't call wait_until_*; let the destructor handle the half-shrunk state.
        }
    }

    TEST(ThreadPoolTests, DestructorWithBackloggedQueueAndShrink)
    {
        // Combination: tasks queued, shrink in flight, then destroy. Workers must drain the
        // queue (because stop_ + tasks_ non-empty falls through to task processing) and exit
        // cleanly without leaking pending_exits_ tokens.
        atomic<int> done(0);
        constexpr int N = 100;
        {
            ThreadPool pool(4);
            for (int i = 0; i < N; i++) {
                pool.enqueue([&done] { done.fetch_add(1, memory_order_acq_rel); });
            }
            pool.set_pool_size(1);
            // Destructor at scope exit; expects all queued tasks to drain.
        }
        ASSERT_EQ(N, done.load());
    }

    TEST(ThreadPoolTests, DestructorWaitsForPendingTasks)
    {
        atomic<int> done(0);
        constexpr int N = 200;
        {
            ThreadPool pool(4);
            for (int i = 0; i < N; i++) {
                pool.enqueue([&done] {
                    this_thread::sleep_for(200us);
                    done.fetch_add(1, memory_order_acq_rel);
                });
            }
            // Pool destructor at scope exit must drain the queue before returning.
        }
        ASSERT_EQ(N, done.load());
    }

    TEST(ThreadPoolTests, MoveOnlyTaskArgs)
    {
        // Ensure the enqueue path handles non-copyable arg types: bind copies its arguments, so
        // the explicit lambda capture is the supported pattern. Verify it works end-to-end.
        ThreadPool pool(1);
        auto p = make_unique<int>(42);
        auto fut = pool.enqueue([up = std::move(p)] { return *up; });
        ASSERT_EQ(42, fut.get());
    }

    TEST(ThreadPoolMgrTests, IsNeitherCopyableNorMovable)
    {
        // A copy takes no reference on the shared pool but its destructor releases one, so the
        // reference count drops while instances still hold the pool. The count is unsigned, so
        // the surplus release underflows it and every later ThreadPoolMgr sees a nonzero count
        // and never recreates the pool, leaving the process permanently unable to run APSI work.
        // The type refusing to be copied is the only thing standing between a caller and that,
        // so assert it at compile time rather than trusting review to catch a reintroduction.
        static_assert(
            !is_copy_constructible_v<ThreadPoolMgr>,
            "ThreadPoolMgr must not be copy constructible");
        static_assert(
            !is_copy_assignable_v<ThreadPoolMgr>, "ThreadPoolMgr must not be copy assignable");
        static_assert(
            !is_move_constructible_v<ThreadPoolMgr>,
            "ThreadPoolMgr must not be move constructible");
        static_assert(
            !is_move_assignable_v<ThreadPoolMgr>, "ThreadPoolMgr must not be move assignable");

        // Nested scopes must still leave the pool usable: this is the pattern the copy would
        // have corrupted, and the reference counting is what makes it work.
        {
            ThreadPoolMgr outer;
            {
                ThreadPoolMgr inner;
                ASSERT_NO_THROW(static_cast<void>(inner.thread_pool()));
            }
            ASSERT_NO_THROW(static_cast<void>(outer.thread_pool()));
        }

        ThreadPoolMgr fresh;
        ASSERT_NO_THROW(static_cast<void>(fresh.thread_pool()));
    }

    TEST(ThreadPoolMgrTests, SetThreadCountTakesEffectOnNextPool)
    {
        // SetThreadCount before any ThreadPoolMgr instance exists must be respected when the pool
        // is constructed. We can't directly observe pool size, so we observe parallelism by
        // pinning N tasks and counting how many run concurrently.
        ThreadPoolMgr::SetThreadCount(3);
        ASSERT_EQ(size_t(3), ThreadPoolMgr::GetThreadCount());

        ThreadPoolMgr tpm;
        promise<void> rel;
        shared_future<void> sf = rel.get_future().share();
        atomic<int> running(0);
        BarrierTask barrier{ &running, sf };

        vector<future<void>> futs;
        futs.reserve(3);
        for (int i = 0; i < 3; i++) {
            futs.push_back(tpm.thread_pool().enqueue(barrier));
        }
        ASSERT_TRUE(spin_until([&] { return running.load() == 3; }));
        rel.set_value();
        for (auto &f : futs) {
            f.get();
        }
    }

    TEST(ThreadPoolMgrTests, SetThreadCountResizesLivePool)
    {
        // The previous behavior (Progsch-style) supported live resize while a pool was alive.
        // SetThreadCount on a live pool must propagate via set_pool_size and grow parallelism.
        ThreadPoolMgr::SetThreadCount(2);
        ThreadPoolMgr tpm;

        // Pin both starting workers.
        promise<void> rel;
        shared_future<void> sf = rel.get_future().share();
        atomic<int> running(0);
        BarrierTask barrier{ &running, sf };
        tpm.thread_pool().enqueue(barrier);
        tpm.thread_pool().enqueue(barrier);
        ASSERT_TRUE(spin_until([&] { return running.load() == 2; }));

        // Grow live.
        ThreadPoolMgr::SetThreadCount(4);
        tpm.thread_pool().enqueue(barrier);
        tpm.thread_pool().enqueue(barrier);
        ASSERT_TRUE(spin_until([&] { return running.load() == 4; }))
            << "SetThreadCount(4) on a live pool did not grow parallelism";

        rel.set_value();
        tpm.thread_pool().wait_until_nothing_in_flight();
    }

    TEST(ThreadPoolTests, ClampPoolSizeStaysWithinBounds)
    {
        ASSERT_LE(ThreadPool::MinPoolSize(), ThreadPool::MaxPoolSize());

        // A pool of zero workers would accept tasks and never run them.
        ASSERT_EQ(ThreadPool::MinPoolSize(), ThreadPool::ClampPoolSize(0));
        ASSERT_EQ(size_t(1), ThreadPool::ClampPoolSize(1));

        // An absurd request is capped rather than allowed to exhaust the thread limit.
        ASSERT_EQ(
            ThreadPool::MaxPoolSize(), ThreadPool::ClampPoolSize(numeric_limits<size_t>::max()));
    }

    TEST(ThreadPoolMgrTests, ThreadCountMatchesActualPoolBounds)
    {
        // Every fan-out site in APSI uses GetThreadCount as a task count, where zero means "run
        // no tasks at all" rather than "run serially", and a count above the pool's cap means
        // enqueueing work no worker will ever claim. GetThreadCount must therefore report a
        // number the pool can actually honor. Values are collected first and the global count is
        // restored before any assertion, so a failure here cannot leak into later tests.
        const size_t max_size = ThreadPool::MaxPoolSize();

        ThreadPoolMgr::SetThreadCount(0);
        const size_t defaulted = ThreadPoolMgr::GetThreadCount();

        ThreadPoolMgr::SetThreadCount(numeric_limits<size_t>::max());
        const size_t clamped = ThreadPoolMgr::GetThreadCount();

        ThreadPoolMgr::SetThreadCount(0);

        ASSERT_LE(ThreadPool::MinPoolSize(), defaulted);
        ASSERT_GE(max_size, defaulted);
        ASSERT_EQ(max_size, clamped);
    }

    TEST(ThreadPoolTests, SetPoolSizeReportsTheSizeItAchieved)
    {
        // Callers publish this number as available capacity, so it has to describe the pool
        // rather than the request. Growth and shrink both settle on the requested value here;
        // the case where they diverge is an operating system refusing to create threads, which
        // a test cannot provoke portably.
        ThreadPool pool(2);
        ASSERT_EQ(size_t(2), pool.pool_size());

        ASSERT_EQ(size_t(4), pool.set_pool_size(4));
        ASSERT_EQ(size_t(4), pool.pool_size());

        // A no-op resize still reports the size in force.
        ASSERT_EQ(size_t(4), pool.set_pool_size(4));

        // Shrinking is asynchronous, but the logical size is reported at once.
        ASSERT_EQ(size_t(1), pool.set_pool_size(1));
        ASSERT_EQ(size_t(1), pool.pool_size());

        // Clamping applies to the reported value too, so it never overstates capacity.
        ASSERT_EQ(ThreadPool::MinPoolSize(), pool.set_pool_size(0));
        ASSERT_EQ(ThreadPool::MaxPoolSize(), pool.set_pool_size(numeric_limits<size_t>::max()));
    }

    TEST(ThreadPoolMgrTests, PoolWorkerCountIsReportedAndNotTheRequestedValue)
    {
        // The worker count is a capacity claim, and a caller that raises it needs to be able to
        // see whether it took effect. GetPoolWorkerCount must therefore follow the pool rather
        // than echo the last request, and must stay independent of the fan-out width.
        ThreadPoolMgr::SetThreadCount(2);
        ThreadPoolMgr tpm;

        const size_t both_set = ThreadPoolMgr::GetPoolWorkerCount();

        ThreadPoolMgr::SetPoolWorkerCount(5);
        const size_t widened_workers = ThreadPoolMgr::GetPoolWorkerCount();
        const size_t widened_fanout = ThreadPoolMgr::GetThreadCount();

        // SetThreadCount resets both, so the worker count follows it back down.
        ThreadPoolMgr::SetThreadCount(3);
        const size_t reset_workers = ThreadPoolMgr::GetPoolWorkerCount();
        const size_t reset_fanout = ThreadPoolMgr::GetThreadCount();

        ThreadPoolMgr::SetThreadCount(0);

        ASSERT_EQ(size_t(2), both_set);
        ASSERT_EQ(size_t(5), widened_workers);
        ASSERT_EQ(size_t(2), widened_fanout);
        ASSERT_EQ(size_t(3), reset_workers);
        ASSERT_EQ(size_t(3), reset_fanout);
    }

    TEST(ThreadPoolMgrTests, DestructionDoesNotHoldTheManagerMutex)
    {
        // ~ThreadPoolMgr destroys the pool, which waits for its workers. It must not hold the
        // manager's mutex while it waits: a worker that calls back into ThreadPoolMgr would block
        // on that mutex while the destructor blocks on the worker, and neither would finish.
        //
        // Provoking that deadlock directly would wedge every later test, so this observes the
        // property that prevents it instead. While a teardown is waiting on a task, an unrelated
        // GetThreadCount must still be served. The gate is opened by a timer rather than by this
        // thread, so if the mutex were held the call would merely be slow -- and the assertion
        // would fail -- rather than hanging the suite.
        promise<void> release;
        shared_future<void> gate = release.get_future().share();

        promise<void> running;
        future<void> running_f = running.get_future();

        thread opener([&release]() {
            this_thread::sleep_for(2s);
            release.set_value();
        });

        thread owner([&running, gate]() {
            ThreadPoolMgr tpm;

            // Fire and forget: nothing waits on this, so it is still running when tpm goes out
            // of scope and the pool's destructor has to drain it.
            (void)tpm.thread_pool().enqueue([&running, gate]() {
                running.set_value();
                gate.wait();
            });
        });

        running_f.wait();

        // Give the owner time to leave the scope and settle into the teardown wait.
        this_thread::sleep_for(100ms);

        auto start = chrono::steady_clock::now();
        (void)ThreadPoolMgr::GetThreadCount();
        auto elapsed = chrono::steady_clock::now() - start;

        owner.join();
        opener.join();

        // Held across teardown, this call would have waited out the whole two-second gate.
        ASSERT_LT(elapsed, 1s);
    }

    TEST(ThreadPoolMgrTests, PoolWorkerCountDoesNotChangeThreadCount)
    {
        // SetPoolWorkerCount raises the pool's worker count above the fan-out width so that
        // concurrent APSI operations can proceed at the same time rather than in sequence. That
        // only works if it leaves the fan-out width alone, which is what this pins down.
        ThreadPoolMgr::SetThreadCount(2);
        ASSERT_EQ(size_t(2), ThreadPoolMgr::GetThreadCount());

        ThreadPoolMgr::SetPoolWorkerCount(4);
        const size_t after_pool_resize = ThreadPoolMgr::GetThreadCount();

        // SetThreadCount, by contrast, resets both, so the ordering of the two calls matters.
        ThreadPoolMgr::SetThreadCount(3);
        const size_t after_thread_count = ThreadPoolMgr::GetThreadCount();

        ThreadPoolMgr::SetThreadCount(0);

        ASSERT_EQ(size_t(2), after_pool_resize);
        ASSERT_EQ(size_t(3), after_thread_count);
    }
} // namespace APSITests
