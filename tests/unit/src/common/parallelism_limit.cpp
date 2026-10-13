// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <initializer_list>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

// APSI
#include "apsi/log.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/task_group.h"
#include "apsi/util/thread_pool.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace std::chrono_literals;
using namespace apsi;
using namespace apsi::util;

namespace APSITests {
    namespace {
        /**
        Spin with a hard deadline so tests fail loudly instead of hanging the suite. Returns
        true if pred became true within the deadline.
        */
        template <typename Pred>
        bool spin_until(Pred pred, chrono::milliseconds deadline = 10000ms)
        {
            auto end = chrono::steady_clock::now() + deadline;
            while (!pred()) {
                if (chrono::steady_clock::now() > end) {
                    return false;
                }
                this_thread::sleep_for(100us);
            }
            return true;
        }

        /**
        Counts the tasks running at once, and the most that ever did
        */
        struct Concurrency {
            atomic<size_t> running{ 0 };

            atomic<size_t> high_water{ 0 };
        };

        /**
        The body of a task that counts itself in the given counters while it runs, and leaves
        only once ready() has held for some task sharing `released`. A test holds the first tasks
        this way until as many run at once as it expects, which catches a group that runs fewer
        at once than it may as well as one that runs more. A wait that times out releases every
        task, and the shortfall then shows in the counts.
        */
        template <typename Ready>
        void counted_task(
            initializer_list<Concurrency *> counters, atomic<bool> &released, Ready ready)
        {
            for (auto *counter : counters) {
                const size_t now = ++counter->running;
                size_t high = counter->high_water.load();
                while (now > high && !counter->high_water.compare_exchange_weak(high, now)) {
                }
            }
            if (ready()) {
                released = true;
            }
            if (!spin_until([&] { return released.load(); })) {
                released = true;
            }
            for (auto *counter : counters) {
                counter->running--;
            }
        }

        /**
        Runs task_count counted tasks in a TaskGroup on the pool, under the limit in effect on the
        calling thread, holding the first until `expected` run at once. Returns the most that
        ever did.
        */
        size_t most_at_once(ThreadPool &pool, size_t task_count, size_t expected)
        {
            Concurrency concurrency;
            atomic<bool> released{ false };
            TaskGroup tasks(pool);
            for (size_t t = 0; t < task_count; t++) {
                tasks.add([&] {
                    counted_task({ &concurrency }, released, [&] {
                        return concurrency.running >= expected;
                    });
                });
            }
            tasks.join();
            return concurrency.high_water;
        }

        /**
        Holds every worker of a pool until `release` is ready, so that tasks queued meanwhile
        wait in the pool's queue in the order they were queued.
        */
        void pin_workers(ThreadPool &pool, size_t worker_count, shared_future<void> release)
        {
            auto pinned = make_shared<atomic<size_t>>(0);
            for (size_t w = 0; w < worker_count; w++) {
                pool.enqueue([pinned, release] {
                    (*pinned)++;
                    release.wait();
                });
            }
            EXPECT_TRUE(spin_until([&] { return pinned->load() == worker_count; }));
        }

        /**
        Begins destroying a pool on another thread and waits until the pool refuses new tasks.
        The caller must have pinned one of its workers, so that the destruction cannot finish
        until the caller releases it; joining the returned thread completes it.
        */
        thread begin_stopping(unique_ptr<ThreadPool> &pool, bool &stopped)
        {
            ThreadPool *raw = pool.get();
            thread destroyer([&pool] { pool.reset(); });
            stopped = spin_until([raw] {
                try {
                    raw->enqueue([] {});
                    return false;
                } catch (const runtime_error &) {
                    return true;
                }
            });
            return destroyer;
        }

        /**
        Not derived from std::exception, so that it can only be caught as itself
        */
        struct IndexedError {
            size_t index;
        };

        struct InjectedError {};

        /**
        A callable that throws from its move constructor once a budget of moves, shared with the
        test, is spent. add() moves the task twice before accepting it, and a larger budget each
        time makes each of those fail in turn.
        */
        struct FailsWhenMoved {
            FailsWhenMoved(atomic<size_t> *r, size_t *b) : runs(r), budget(b)
            {}

            // NOLINTNEXTLINE(performance-noexcept-move-constructor): throwing is the point
            FailsWhenMoved(FailsWhenMoved &&other) : runs(other.runs), budget(other.budget)
            {
                if (!*budget) {
                    throw InjectedError{};
                }
                (*budget)--;
            }

            void operator()() const
            {
                (*runs)++;
            }

            atomic<size_t> *runs;

            size_t *budget;
        };

        /**
        Contracts of a TaskGroup that depend on the limit, without one and under limits of 1,
        2 and 4. Those that do not are in task_group.cpp, where they run under the same limits.
        */
        class TaskGroupLimitTests : public testing::TestWithParam<size_t> {};
    } // namespace

    TEST(ScopedParallelismLimitTests, IsNeitherCopyableNorMovable)
    {
        // A copy would restore the enclosing limit a second time when destroyed, and a moved-from
        // limit would restore it while the moved-to one is still alive.
        static_assert(!is_copy_constructible_v<ScopedParallelismLimit>);
        static_assert(!is_copy_assignable_v<ScopedParallelismLimit>);
        static_assert(!is_move_constructible_v<ScopedParallelismLimit>);
        static_assert(!is_move_assignable_v<ScopedParallelismLimit>);
    }

    TEST(ScopedParallelismLimitTests, NestedLimitsTakeTheSmallestAndZeroAddsNone)
    {
        ASSERT_EQ(size_t(0), parallelism_limit());
        {
            ScopedParallelismLimit none(0);
            EXPECT_EQ(size_t(0), parallelism_limit());
            ScopedParallelismLimit outer(4);
            EXPECT_EQ(size_t(4), parallelism_limit());
            {
                ScopedParallelismLimit inner(2);
                EXPECT_EQ(size_t(2), parallelism_limit());

                // Neither a larger limit nor zero raises a smaller one.
                ScopedParallelismLimit wider(8);
                ScopedParallelismLimit zero(0);
                EXPECT_EQ(size_t(2), parallelism_limit());
            }
            EXPECT_EQ(size_t(4), parallelism_limit());
        }
        EXPECT_EQ(size_t(0), parallelism_limit());
    }

    TEST(ScopedParallelismLimitTests, WorksWithSetThreadCountAndSetPoolWorkerCount)
    {
        // GetThreadCount, by which the stride-based fan-outs size themselves, reports the smaller
        // of the limit and the width on the limited thread, and the width on other threads and
        // once the limit is gone. How many tasks a group runs at once is bounded by the limit and
        // by the pool's workers, whatever the width. Values are collected first and the global
        // count is restored before any assertion.
        ThreadPoolMgr::SetThreadCount(2);
        size_t above_width = 0;
        size_t one_worker = 0;
        size_t six_workers = 0;
        size_t after_workers = 0;
        size_t below_width = 0;
        size_t elsewhere = 0;
        {
            ScopedParallelismLimit limit(3);
            above_width = ThreadPoolMgr::GetThreadCount();
            {
                ThreadPoolMgr tpm;
                ThreadPoolMgr::SetPoolWorkerCount(1);
                one_worker = most_at_once(tpm.thread_pool(), 12, 1);
            }
            {
                ThreadPoolMgr tpm;
                ThreadPoolMgr::SetPoolWorkerCount(6);
                six_workers = most_at_once(tpm.thread_pool(), 12, 3);
            }
            after_workers = ThreadPoolMgr::GetThreadCount();

            ThreadPoolMgr::SetThreadCount(8);
            below_width = ThreadPoolMgr::GetThreadCount();
            thread([&] { elsewhere = ThreadPoolMgr::GetThreadCount(); }).join();
        }
        const size_t after = ThreadPoolMgr::GetThreadCount();

        ThreadPoolMgr::SetThreadCount(0);

        EXPECT_EQ(size_t(2), above_width);
        EXPECT_EQ(size_t(1), one_worker);
        EXPECT_EQ(size_t(3), six_workers);
        EXPECT_EQ(size_t(2), after_workers);
        EXPECT_EQ(size_t(3), below_width);
        EXPECT_EQ(size_t(8), elsewhere);
        EXPECT_EQ(size_t(8), after);
    }

    TEST(ScopedParallelismLimitTests, OutlivesThePoolBeingTornDownAndRecreated)
    {
        // The limit belongs to the thread, not to the pool, so it stays in effect while the shared
        // pool is destroyed with its last ThreadPoolMgr and created again with the next.
        ThreadPoolMgr::SetThreadCount(4);
        ScopedParallelismLimit limit(2);

        vector<size_t> widths;
        vector<size_t> high_waters;
        for (int round = 0; round < 3; round++) {
            ThreadPoolMgr tpm;
            widths.push_back(ThreadPoolMgr::GetThreadCount());
            high_waters.push_back(most_at_once(tpm.thread_pool(), 16, 2));
        }

        ThreadPoolMgr::SetThreadCount(0);

        EXPECT_EQ(vector<size_t>(3, 2), widths);
        EXPECT_EQ(vector<size_t>(3, 2), high_waters);
    }

    TEST(ScopedParallelismLimitDeathTest, MustBeDestroyedInOrderOnItsThread)
    {
#ifdef NDEBUG
        GTEST_SKIP() << "Checked only in debug builds";
#else
        GTEST_FLAG_SET(death_test_style, "threadsafe");

        EXPECT_DEATH(
            {
                auto *limit = new ScopedParallelismLimit(2);
                thread([limit] { delete limit; }).join();
            },
            "ScopedParallelismLimit");

        EXPECT_DEATH(
            {
                auto *outer = new ScopedParallelismLimit(2);
                ScopedParallelismLimit inner(1);
                delete outer;
            },
            "ScopedParallelismLimit");
#endif
    }

    TEST_P(TaskGroupLimitTests, RunsAtMostTheLimitAtOnce)
    {
        // Without a limit, as many as the pool has workers
        constexpr size_t worker_count = 8;
        ThreadPool pool(worker_count);
        const size_t expected = GetParam() ? GetParam() : worker_count;

        ScopedParallelismLimit scope(GetParam());
        EXPECT_EQ(expected, most_at_once(pool, 64, expected));
    }

    TEST_P(TaskGroupLimitTests, RunsEveryTaskOnceWhileAddRacesWithRunners)
    {
        // Tasks that finish at once leave runners finding nothing more to do while the next add()
        // is under way, so add() keeps having to admit a replacement. Rounds of every size,
        // joined in between, reuse one group, and size() counts from the last join(). Every task
        // runs exactly once, and never on the thread that added it.
        constexpr size_t round_count = 300;
        ThreadPool pool(4);
        vector<atomic<int>> runs(round_count * 12);
        atomic<size_t> on_adding_thread{ 0 };
        const thread::id adding_thread = this_thread::get_id();
        size_t added = 0;

        ScopedParallelismLimit scope(GetParam());
        TaskGroup tasks(pool);
        for (size_t round = 0; round < round_count; round++) {
            const size_t count = round % 13;
            for (size_t t = 0; t < count; t++) {
                tasks.add([&, task = added + t] {
                    runs[task]++;
                    if (this_thread::get_id() == adding_thread) {
                        on_adding_thread++;
                    }
                });
                if (t % 4 == 0) {
                    this_thread::yield();
                }
            }
            added += count;

            EXPECT_EQ(count, tasks.size());
            tasks.join();
            EXPECT_EQ(size_t(0), tasks.size());
        }

        size_t ran_once = 0;
        for (size_t task = 0; task < added; task++) {
            ran_once += (runs[task].load() == 1) ? 1 : 0;
        }
        EXPECT_EQ(added, ran_once);
        EXPECT_EQ(size_t(0), on_adding_thread.load());
    }

    TEST_P(TaskGroupLimitTests, JoinRethrowsTheFirstExceptionOfAnyTypeByAddOrder)
    {
        // Failing tasks throw exceptions of different types, standard and not, and finish in the
        // reverse of the order they were added: as many as run at once, so that each can wait
        // for those added after it. A runner catches whatever a task throws and goes on, so a
        // last task that does not fail, waiting in the group until a runner is free, still runs,
        // and join() waits for it too before rethrowing the first exception by add order.
        const size_t failing = GetParam() ? GetParam() : 4;
        ThreadPool pool(failing);
        atomic<size_t> failed{ 0 };
        atomic<bool> last_finished{ false };

        ScopedParallelismLimit scope(GetParam());
        TaskGroup tasks(pool);
        for (size_t t = 0; t < failing; t++) {
            tasks.add([&failed, failing, t] {
                EXPECT_TRUE(spin_until([&] { return failed.load() == failing - 1 - t; }));
                failed++;
                if (t % 3 == 0) {
                    throw IndexedError{ t };
                }
                if (t % 3 == 1) {
                    throw static_cast<int>(t);
                }
                throw runtime_error("standard");
            });
        }
        tasks.add([&last_finished] {
            this_thread::sleep_for(20ms);
            last_finished = true;
        });

        size_t thrown = failing;
        try {
            tasks.join();
        } catch (const IndexedError &ex) {
            thrown = ex.index;
        }
        EXPECT_EQ(size_t(0), thrown);
        EXPECT_EQ(failing, failed.load());
        EXPECT_TRUE(last_finished.load());
    }

    TEST_P(TaskGroupLimitTests, RefusesJoinFromItsOwnTask)
    {
        // A task that joins its own group would wait for itself. It is refused instead, and the
        // owner's join() then sees the refusal as the task's exception.
        ThreadPool pool(2);
        promise<bool> refused;

        ScopedParallelismLimit limit(GetParam());
        TaskGroup tasks(pool);
        tasks.add([&tasks, &refused] {
            try {
                tasks.join();
                refused.set_value(false);
            } catch (const logic_error &) {
                refused.set_value(true);
                throw;
            }
        });

        EXPECT_TRUE(refused.get_future().get());
        EXPECT_THROW(tasks.join(), logic_error);
    }

    INSTANTIATE_TEST_SUITE_P(
        Limits, TaskGroupLimitTests, testing::Values(size_t(0), size_t(1), size_t(2), size_t(4)));

    TEST(TaskGroupLimitDeathTest, TerminatesWhenDestroyedByItsOwnTask)
    {
        // A destructor cannot refuse by throwing, nor wait for the task it is running in, so it
        // terminates the process with a message rather than hang, with or without a limit.
        GTEST_FLAG_SET(death_test_style, "threadsafe");
        for (size_t limit : { size_t(0), size_t(1) }) {
            EXPECT_DEATH(
                {
                    SetLogLevel(LogLevel::error);
                    ThreadPool pool(1);
                    ScopedParallelismLimit scope(limit);
                    auto *tasks = new TaskGroup(pool);
                    tasks->add([tasks] { delete tasks; });
                    this_thread::sleep_for(60s);
                },
                "TaskGroup destroyed");
        }
    }

    TEST(LimitedTaskGroupTests, AddThatThrowsLeavesTheGroupAsItWas)
    {
        // add() moves the task twice before accepting it; make each move fail in turn. A failed
        // add() must not change size(), nor run the task, nor disturb the tasks added before it.
        ThreadPool pool(2);
        atomic<size_t> earlier_runs{ 0 };
        atomic<size_t> runs{ 0 };

        ScopedParallelismLimit scope(2);
        TaskGroup tasks(pool);
        tasks.add([&earlier_runs] { earlier_runs++; });

        size_t failures = 0;
        for (size_t budget = 0;; budget++) {
            ASSERT_LT(budget, size_t(16)) << "add() never succeeded";
            size_t left = budget;
            const size_t size_before = tasks.size();
            try {
                tasks.add(FailsWhenMoved(&runs, &left));
                break;
            } catch (const InjectedError &) {
                failures++;
                EXPECT_EQ(size_before, tasks.size());
            }
        }

        EXPECT_LT(size_t(0), failures);
        EXPECT_EQ(size_t(2), tasks.size());
        EXPECT_NO_THROW(tasks.join());
        EXPECT_EQ(size_t(1), earlier_runs.load());
        EXPECT_EQ(size_t(1), runs.load());
    }

    TEST(LimitedTaskGroupTests, NothingIsLeftBehindWhenThePoolRefusesARunner)
    {
        // A pool that is being destroyed refuses new tasks. One of its two workers is pinned, so
        // that it cannot finish stopping before the test is done with it, and the other runs the
        // first task of a group with a limit of one, while the second waits in the group.
        auto pool = make_unique<ThreadPool>(2);
        promise<void> release;
        pin_workers(*pool, 1, release.get_future().share());

        ThreadPool &stopping = *pool;
        promise<void> first_running;
        promise<void> first_release;
        shared_future<void> first_gate = first_release.get_future().share();
        atomic<bool> second_ran{ false };
        atomic<bool> refused_ran{ false };
        bool refused = false;
        size_t refused_size = 1;
        bool stopped = false;
        thread destroyer;
        {
            ScopedParallelismLimit limit(1);
            TaskGroup tasks(stopping);
            tasks.add([&first_running, first_gate] {
                first_running.set_value();
                first_gate.wait();
            });
            tasks.add([&second_ran] { second_ran = true; });
            first_running.get_future().wait();
            destroyer = begin_stopping(pool, stopped);

            // add() queues a group's first runner only after it has taken the task in, so it has
            // to withdraw the task when the pool refuses the runner, and fail as if never called.
            if (stopped) {
                TaskGroup other(stopping);
                try {
                    other.add([&refused_ran] { refused_ran = true; });
                } catch (const runtime_error &) {
                    refused = true;
                }
                refused_size = other.size();
                EXPECT_NO_THROW(other.join());
            }

            // The runner cannot queue itself again for the second task, so it must run it itself:
            // nothing else would.
            first_release.set_value();
            EXPECT_NO_THROW(tasks.join());
        }

        release.set_value();
        destroyer.join();

        ASSERT_TRUE(stopped);
        EXPECT_TRUE(refused);
        EXPECT_EQ(size_t(0), refused_size);
        EXPECT_FALSE(refused_ran.load());
        EXPECT_TRUE(second_ran.load());
    }

    TEST(LimitedTaskGroupTests, AShortGroupStartsBeforeALongOneFinishes)
    {
        // A runner queues itself again after each task, behind whatever was queued meanwhile. The
        // long group's two runners are both held in a task when the short group's task is queued,
        // so it is first in the pool's queue, and they queue behind it once released. The one
        // long task the other worker can then start before it, the seventh, waits for it, so
        // that nothing depends on how the two workers are scheduled.
        ThreadPool pool(2);
        constexpr size_t long_count = 10;
        promise<void> release;
        shared_future<void> held = release.get_future().share();
        atomic<size_t> long_started{ 0 };
        atomic<bool> short_started{ false };
        atomic<bool> long_done{ false };

        auto long_group = async(launch::async, [&] {
            ScopedParallelismLimit limit(2);
            TaskGroup tasks(pool);
            for (size_t t = 0; t < long_count; t++) {
                tasks.add([&, t] {
                    long_started++;
                    if (t == 4 || t == 5) {
                        held.wait();
                    } else if (t > 5) {
                        EXPECT_TRUE(spin_until([&] { return short_started.load(); }));
                    }
                });
            }
            tasks.join();
            long_done = true;
        });

        // Both runners are now held in a task, and neither is queued.
        EXPECT_TRUE(spin_until([&] { return long_started.load() == 6; }));

        size_t started_when_run = 0;
        bool long_done_when_run = true;
        {
            ScopedParallelismLimit limit(1);
            TaskGroup tasks(pool);
            tasks.add([&] {
                started_when_run = long_started.load();
                long_done_when_run = long_done.load();
                short_started = true;
            });
            release.set_value();
            tasks.join();
        }
        long_group.get();

        EXPECT_LE(started_when_run, size_t(7));
        EXPECT_FALSE(long_done_when_run);
    }

    TEST(LimitedTaskGroupTests, ManyGroupsWithALimitOfOneAllProgress)
    {
        // Eight operations, each limited to one task at a time, share a worker. It is held until
        // every operation has added its tasks, so that the pool's queue holds the eight runners
        // and nothing else. A runner queues itself again behind the others after each task, so
        // the first task of every operation runs before the second of any. With more workers,
        // one held up between taking a runner and starting its task would let the others run
        // later tasks first, and the order would depend on scheduling.
        ThreadPool pool(1);
        constexpr size_t group_count = 8;
        constexpr size_t task_count = 10;
        promise<void> release;
        pin_workers(pool, 1, release.get_future().share());

        atomic<size_t> added{ 0 };
        atomic<size_t> runs{ 0 };
        vector<size_t> first_run(group_count, numeric_limits<size_t>::max());
        vector<future<size_t>> groups;
        for (size_t g = 0; g < group_count; g++) {
            groups.push_back(async(launch::async, [&, g] {
                ScopedParallelismLimit limit(1);
                atomic<size_t> ran{ 0 };
                TaskGroup tasks(pool);
                for (size_t t = 0; t < task_count; t++) {
                    tasks.add([&, g, t] {
                        const size_t run = runs++;
                        if (!t) {
                            first_run[g] = run;
                        }
                        ran++;
                    });
                }
                added++;
                tasks.join();
                return ran.load();
            }));
        }
        EXPECT_TRUE(spin_until([&] { return added.load() == group_count; }));
        release.set_value();

        for (auto &group : groups) {
            EXPECT_EQ(task_count, group.get());
        }
        for (size_t g = 0; g < group_count; g++) {
            EXPECT_LT(first_run[g], group_count) << "group " << g;
        }
    }

    TEST(LimitedTaskGroupTests, LimitsOnDifferentThreadsAreIndependent)
    {
        // Two threads hold limits of 1 and 3 at once, and their operations share a pool of 8
        // workers. Each stays within its own limit, and they neither wait for each other nor share
        // a budget: the first tasks of both are held until both run as many tasks as their limits
        // allow, at the same time.
        ThreadPool pool(8);
        Concurrency one;
        Concurrency three;
        Concurrency both;
        atomic<bool> released{ false };

        auto run = [&](size_t max_tasks, Concurrency &mine) {
            ScopedParallelismLimit limit(max_tasks);
            TaskGroup tasks(pool);
            for (size_t t = 0; t < 30; t++) {
                tasks.add([&] {
                    counted_task({ &mine, &both }, released, [&] {
                        return one.running == 1 && three.running == 3;
                    });
                });
            }
            tasks.join();
        };

        auto first = async(launch::async, run, size_t(1), ref(one));
        auto second = async(launch::async, run, size_t(3), ref(three));
        first.get();
        second.get();

        EXPECT_EQ(size_t(1), one.high_water.load());
        EXPECT_EQ(size_t(3), three.high_water.load());
        EXPECT_EQ(size_t(4), both.high_water.load());
    }
} // namespace APSITests
