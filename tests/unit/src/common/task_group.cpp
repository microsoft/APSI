// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

// APSI
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/task_group.h"
#include "apsi/util/thread_pool.h"

// GTest
#include "gtest/gtest.h"

using namespace std;
using namespace std::chrono_literals;
using namespace apsi;
using namespace apsi::util;

namespace APSITests {
    namespace {
        // Distinct, unrelated types so "first exception wins" cannot be satisfied by accident.
        // Note std::future_error derives from std::logic_error, so asserting on a standard
        // exception type would let a wrong implementation pass for the wrong reason.
        struct FirstError : runtime_error {
            FirstError() : runtime_error("first")
            {}
        };

        struct SecondError : runtime_error {
            SecondError() : runtime_error("second")
            {}
        };

        // Every contract below holds with or without a parallelism limit, so each test runs
        // without one and under limits of 1, 2 and 4.
        class TaskGroupTests : public testing::TestWithParam<size_t> {};
    } // namespace

    TEST_P(TaskGroupTests, JoinWaitsForEveryTaskDespiteAnEarlyThrow)
    {
        // The whole point of the class. A plain "for (f : futures) f.get();" rethrows on the
        // first failing task and abandons the rest, which keep running against the caller's
        // locals while the caller unwinds and destroys them.
        constexpr size_t task_count = 8;
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < task_count; t++) {
            tasks.add([&finished, t] {
                if (t == 0) {
                    throw FirstError{};
                }
                this_thread::sleep_for(20ms);
                finished++;
            });
        }

        ASSERT_THROW(tasks.join(), FirstError);

        // Every surviving task ran to completion before join() returned control.
        ASSERT_EQ(task_count - 1, finished.load());
    }

    TEST_P(TaskGroupTests, JoinRethrowsTheFirstExceptionByAddOrder)
    {
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;

        // Make the LAST task fail first in time, so a "first failure wins" implementation would
        // surface SecondError. join() must report by the order tasks were added instead. With a
        // limit of one the tasks run in order, which join() must report all the same.
        promise<void> gate;
        shared_future<void> gate_future = gate.get_future().share();

        TaskGroup tasks(tpm.thread_pool());
        tasks.add([gate_future] {
            gate_future.wait();
            throw FirstError{};
        });
        tasks.add([] { throw SecondError{}; });

        // Let the second task fail before the first is even allowed to start failing.
        this_thread::sleep_for(20ms);
        gate.set_value();

        ASSERT_THROW(tasks.join(), FirstError);
    }

    TEST_P(TaskGroupTests, ForgettingJoinStillWaitsForEveryTask)
    {
        // The safety property that makes this design hard to misuse: a caller who never calls
        // join() -- or who leaves the scope by an exception thrown while tasks are still being
        // added -- loses the task exceptions but never leaks a running task. With a limit, the
        // destructor begins while tasks are still waiting for a runner.
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t task_count = 4;

        {
            TaskGroup tasks(tpm.thread_pool());
            for (size_t t = 0; t < task_count; t++) {
                tasks.add([&finished] {
                    this_thread::sleep_for(20ms);
                    finished++;
                });
            }
            // No join(); the destructor below must still wait.
        }

        ASSERT_EQ(task_count, finished.load());
    }

    TEST_P(TaskGroupTests, DestructorWaitsWhenTheAddLoopThrows)
    {
        // add() allocates, so it can throw partway through fanning out, before join() is ever
        // reached. The already-started tasks must not be abandoned.
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t added_before_failure = 4;

        bool threw = false;
        try {
            TaskGroup tasks(tpm.thread_pool());

            for (size_t t = 0; t < added_before_failure; t++) {
                tasks.add([&finished] {
                    this_thread::sleep_for(20ms);
                    finished++;
                });
            }

            // Stand in for a throwing add(); the destructor runs as this scope unwinds.
            throw runtime_error("add failed");
        } catch (const runtime_error &) {
            threw = true;
        }

        ASSERT_TRUE(threw);
        ASSERT_EQ(added_before_failure, finished.load());
    }

    TEST_P(TaskGroupTests, DestructorSwallowsTaskExceptions)
    {
        // The destructor is implicitly noexcept; letting a task exception escape it would call
        // std::terminate.
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;

        ASSERT_NO_THROW({
            TaskGroup tasks(tpm.thread_pool());
            tasks.add([]() { throw FirstError{}; });
            tasks.add([]() { throw SecondError{}; });
        });
    }

    TEST_P(TaskGroupTests, JoinIsIdempotentAndLeavesTheGroupEmpty)
    {
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < 4; t++) {
            tasks.add([&finished] { finished++; });
        }

        ASSERT_EQ(static_cast<size_t>(4), tasks.size());
        ASSERT_NO_THROW(tasks.join());

        // Consumed, so a second join() and the destructor are both no-ops.
        ASSERT_EQ(static_cast<size_t>(0), tasks.size());
        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(static_cast<size_t>(4), finished.load());
    }

    TEST_P(TaskGroupTests, JoinOnAnEmptyGroupIsANoOp)
    {
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;

        TaskGroup tasks(tpm.thread_pool());
        ASSERT_EQ(static_cast<size_t>(0), tasks.size());
        ASSERT_NO_THROW(tasks.join());
    }

    TEST_P(TaskGroupTests, AddKeepsEveryTaskAcrossReallocation)
    {
        // The internal containers grow repeatedly here; no task may be lost along the way.
        // Without a limit, add() stores the future before queueing the task precisely so that a
        // reallocation failure cannot strand a running task outside the group.
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t task_count = 64;

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < task_count; t++) {
            tasks.add([&finished] { finished++; });
        }

        ASSERT_EQ(task_count, tasks.size());
        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(task_count, finished.load());
    }

    TEST_P(TaskGroupTests, AddForwardsTrailingArguments)
    {
        // Matches ThreadPool::enqueue's (callable, args...) form, which the OPRF call sites use
        // to hand each task its slice index. A move-only callable is accepted as well.
        ScopedParallelismLimit scope(GetParam());
        ThreadPoolMgr tpm;
        atomic<size_t> total{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        auto worker = [&total](size_t start_idx, size_t step) {
            total += start_idx + step;
        };
        for (size_t t = 0; t < 4; t++) {
            tasks.add(worker, t, static_cast<size_t>(10));
        }
        tasks.add([p = make_unique<size_t>(100), &total] { total += *p; });

        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(static_cast<size_t>(146), total.load());
    }

    TEST_P(TaskGroupTests, RejectsUseFromInsideItsOwnPool)
    {
        // Adding to a group backed by the pool the caller is running on is the step that makes a
        // deadlock possible: join() would then block a worker on work only that pool can run.
        // It is refused outright, so the mistake surfaces as an error where it is made rather
        // than as a hang whose cause is somewhere else entirely. The refused group then has
        // nothing to wait for as it is destroyed on the worker. The limit is created in the task,
        // since it belongs to the thread that creates the group.
        ThreadPool pool(2);

        auto fut = pool.enqueue([&pool, limit = GetParam()] {
            ScopedParallelismLimit scope(limit);
            TaskGroup nested(pool);
            nested.add([] {});
        });

        ASSERT_THROW(fut.get(), logic_error);
    }

    TEST_P(TaskGroupTests, AllowsUseFromAWorkerOfADifferentPool)
    {
        // The guard is about waiting on the pool you occupy. A worker of one pool waiting on a
        // different pool cannot starve it, and must keep working.
        ThreadPool pool_a(1);
        ThreadPool pool_b(2);

        auto fut = pool_a.enqueue([&pool_b, limit = GetParam()] {
            ScopedParallelismLimit scope(limit);
            TaskGroup tasks(pool_b);
            atomic<int> ran{ 0 };
            tasks.add([&ran] { ran++; });
            tasks.join();
            return ran.load();
        });

        ASSERT_EQ(1, fut.get());
    }

    INSTANTIATE_TEST_SUITE_P(
        Limits, TaskGroupTests, testing::Values(size_t(0), size_t(1), size_t(2), size_t(4)));
} // namespace APSITests
