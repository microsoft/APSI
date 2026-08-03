// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstddef>
#include <future>
#include <stdexcept>
#include <thread>
#include <vector>

// APSI
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/task_group.h"

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
    } // namespace

    TEST(TaskGroupTests, JoinWaitsForEveryTaskDespiteAnEarlyThrow)
    {
        // The whole point of the class. A plain "for (f : futures) f.get();" rethrows on the
        // first failing task and abandons the rest, which keep running against the caller's
        // locals while the caller unwinds and destroys them.
        constexpr size_t task_count = 8;
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < task_count; t++) {
            tasks.add([&finished, t]() {
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

    TEST(TaskGroupTests, JoinRethrowsTheFirstExceptionByAddOrder)
    {
        ThreadPoolMgr tpm;

        // Make the LAST task fail first in time, so a "first failure wins" implementation would
        // surface SecondError. join() must report by the order tasks were added instead.
        promise<void> gate;
        shared_future<void> gate_future = gate.get_future().share();

        TaskGroup tasks(tpm.thread_pool());
        tasks.add([gate_future]() {
            gate_future.wait();
            throw FirstError{};
        });
        tasks.add([]() { throw SecondError{}; });

        // Let the second task fail before the first is even allowed to start failing.
        this_thread::sleep_for(20ms);
        gate.set_value();

        ASSERT_THROW(tasks.join(), FirstError);
    }

    TEST(TaskGroupTests, ForgettingJoinStillWaitsForEveryTask)
    {
        // The safety property that makes this design hard to misuse: a caller who never calls
        // join() -- or who leaves the scope by an exception thrown while tasks are still being
        // added -- loses the task exceptions but never leaks a running task.
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t task_count = 4;

        {
            TaskGroup tasks(tpm.thread_pool());
            for (size_t t = 0; t < task_count; t++) {
                tasks.add([&finished]() {
                    this_thread::sleep_for(20ms);
                    finished++;
                });
            }
            // No join(); the destructor below must still wait.
        }

        ASSERT_EQ(task_count, finished.load());
    }

    TEST(TaskGroupTests, DestructorWaitsWhenTheAddLoopThrows)
    {
        // add() allocates, so it can throw partway through fanning out, before join() is ever
        // reached. The already-started tasks must not be abandoned.
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t added_before_failure = 4;

        bool threw = false;
        try {
            TaskGroup tasks(tpm.thread_pool());

            for (size_t t = 0; t < added_before_failure; t++) {
                tasks.add([&finished]() {
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

    TEST(TaskGroupTests, DestructorSwallowsTaskExceptions)
    {
        // The destructor is implicitly noexcept; letting a task exception escape it would call
        // std::terminate.
        ThreadPoolMgr tpm;

        ASSERT_NO_THROW({
            TaskGroup tasks(tpm.thread_pool());
            tasks.add([]() { throw FirstError{}; });
            tasks.add([]() { throw SecondError{}; });
        });
    }

    TEST(TaskGroupTests, JoinIsIdempotentAndLeavesTheGroupEmpty)
    {
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < 4; t++) {
            tasks.add([&finished]() { finished++; });
        }

        ASSERT_EQ(static_cast<size_t>(4), tasks.size());
        ASSERT_NO_THROW(tasks.join());

        // Consumed, so a second join() and the destructor are both no-ops.
        ASSERT_EQ(static_cast<size_t>(0), tasks.size());
        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(static_cast<size_t>(4), finished.load());
    }

    TEST(TaskGroupTests, JoinOnAnEmptyGroupIsANoOp)
    {
        ThreadPoolMgr tpm;

        TaskGroup tasks(tpm.thread_pool());
        ASSERT_EQ(static_cast<size_t>(0), tasks.size());
        ASSERT_NO_THROW(tasks.join());
    }

    TEST(TaskGroupTests, AddKeepsEveryTaskAcrossReallocation)
    {
        // The internal container reallocates repeatedly here; no task may be lost along the way.
        // add() stores the future before queueing the task precisely so that a reallocation
        // failure cannot strand a running task outside the group.
        ThreadPoolMgr tpm;
        atomic<size_t> finished{ 0 };
        constexpr size_t task_count = 64;

        TaskGroup tasks(tpm.thread_pool());
        for (size_t t = 0; t < task_count; t++) {
            tasks.add([&finished]() { finished++; });
        }

        ASSERT_EQ(task_count, tasks.size());
        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(task_count, finished.load());
    }

    TEST(TaskGroupTests, AddForwardsTrailingArguments)
    {
        // Matches ThreadPool::enqueue's (callable, args...) form, which the OPRF call sites use
        // to hand each task its slice index.
        ThreadPoolMgr tpm;
        atomic<size_t> total{ 0 };

        TaskGroup tasks(tpm.thread_pool());
        auto worker = [&total](size_t start_idx, size_t step) {
            total += start_idx + step;
        };
        for (size_t t = 0; t < 4; t++) {
            tasks.add(worker, t, static_cast<size_t>(10));
        }

        ASSERT_NO_THROW(tasks.join());
        ASSERT_EQ(static_cast<size_t>(46), total.load());
    }
} // namespace APSITests
