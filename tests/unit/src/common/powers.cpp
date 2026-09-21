// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iostream>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

// APSI
#include "apsi/powers.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/utils.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests {
    TEST(PowersTests, PowersDagConfigure)
    {
        PowersDag pd;
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        set<uint32_t> source_powers = {};
        set<uint32_t> target_powers = {};
        ASSERT_FALSE(pd.configure(source_powers, target_powers));
        ASSERT_FALSE(pd.is_configured());
        ASSERT_FALSE(pd.configure(source_powers, { 1 }));
        ASSERT_FALSE(pd.is_configured());

        // Check for member variables
        ASSERT_THROW(static_cast<void>(pd.depth()), logic_error);
        ASSERT_THROW(static_cast<void>(pd.source_count()), logic_error);
        ASSERT_THROW(static_cast<void>(pd.target_powers()), logic_error);

        // Bad configuration
        source_powers = { 0, 1 };
        ASSERT_FALSE(pd.configure(source_powers, { 0 }));
        ASSERT_FALSE(pd.is_configured());
        ASSERT_FALSE(pd.configure(source_powers, { 1 }));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        source_powers = { 2, 3 };
        ASSERT_FALSE(pd.configure(source_powers, { 0 }));
        ASSERT_FALSE(pd.is_configured());
        ASSERT_FALSE(pd.configure(source_powers, { 1 }));
        ASSERT_FALSE(pd.is_configured());
        ASSERT_FALSE(pd.configure(source_powers, { 1, 2 }));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        source_powers = { 1 };
        ASSERT_FALSE(pd.configure(source_powers, { 0 }));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        source_powers = { 1, 2 };
        ASSERT_FALSE(pd.configure(source_powers, { 1 }));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        source_powers = { 1, 3 };
        ASSERT_FALSE(pd.configure(source_powers, { 1, 2 }));
        ASSERT_FALSE(pd.is_configured());

        // Good configuration; required depth is 0
        source_powers = { 1 };
        ASSERT_TRUE(pd.configure(source_powers, { 1 }));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(1, pd.target_powers().size());

        // Good configuration; required depth is 0
        source_powers = { 1 };
        ASSERT_TRUE(pd.configure(source_powers, { 1, 2 }));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(1, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(2, pd.target_powers().size());

        // Good configuration; required depth is 0
        source_powers = { 1, 2 };
        ASSERT_TRUE(pd.configure(source_powers, source_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(2, pd.source_count());
        ASSERT_EQ(2, pd.target_powers().size());

        // Good configuration; required depth is 1
        source_powers = { 1, 3, 4 };
        target_powers = create_powers_set(0, 8);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(1, pd.depth());
        ASSERT_EQ(3, pd.source_count());
        ASSERT_EQ(8, pd.target_powers().size());

        // Good configuration; required depth is 1
        source_powers = { 1, 2, 5, 8, 11, 14, 15, 16 };
        target_powers = create_powers_set(0, 32);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(1, pd.depth());
        ASSERT_EQ(8, pd.source_count());
        ASSERT_EQ(32, pd.target_powers().size());

        // Good configuration; required depth is 2
        source_powers = { 1, 4, 5 };
        target_powers = create_powers_set(0, 15);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(2, pd.depth());
        ASSERT_EQ(3, pd.source_count());
        ASSERT_EQ(15, pd.target_powers().size());

        // Good configuration; required depth is 2
        source_powers = { 1, 3, 11, 15, 32 };
        target_powers = create_powers_set(0, 70);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(2, pd.depth());
        ASSERT_EQ(5, pd.source_count());
        ASSERT_EQ(70, pd.target_powers().size());

        // Good configuration; required depth is 3
        source_powers = { 1, 3, 11, 15, 32 };
        target_powers = create_powers_set(0, 71);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(3, pd.depth());
        ASSERT_EQ(5, pd.source_count());
        ASSERT_EQ(71, pd.target_powers().size());

        // Clear data
        pd.reset();
        ASSERT_FALSE(pd.is_configured());

        // Good configuration; required depth is 3
        source_powers = { 1, 8, 13, 58, 169, 295, 831, 1036 };
        target_powers = create_powers_set(0, 3485);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(3, pd.depth());
        ASSERT_EQ(8, pd.source_count());
        ASSERT_EQ(3485, pd.target_powers().size());

        // Good configuration; required depth is 4
        source_powers = { 1, 8, 13, 58, 169, 295, 831, 1036 };
        target_powers = create_powers_set(0, 3486);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(4, pd.depth());
        ASSERT_EQ(8, pd.source_count());
        ASSERT_EQ(3486, pd.target_powers().size());
    }

    TEST(PowersTest, Apply)
    {
        PowersDag pd;
        set<uint32_t> source_powers = { 1, 8, 13, 58, 169, 295, 831, 1036 };
        set<uint32_t> target_powers = create_powers_set(0, 3485);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));
        ASSERT_TRUE(pd.is_configured());

        // Expected values
        vector<uint32_t> expected(3485);
        iota(expected.begin(), expected.end(), 1);

        // Real results
        vector<uint32_t> real;
        pd.apply([&](auto &node) { real.push_back(node.power); });

        // Compare
        ASSERT_EQ(expected.size(), real.size());
        ASSERT_TRUE(equal(expected.begin(), expected.end(), real.begin()));
    }

    namespace {
        struct ApplyOutcome {
            bool threw = false;
        };

        /**
        Sets the shared thread pool size for the duration of a test and restores the default on
        scope exit. A trailing SetThreadCount call in the test body is skipped whenever an ASSERT_*
        fires, which would leak the oversized pool into whichever test runs next.
        */
        class ScopedThreadCount {
        public:
            explicit ScopedThreadCount(size_t threads)
            {
                ThreadPoolMgr::SetThreadCount(threads);
            }

            ~ScopedThreadCount()
            {
                ThreadPoolMgr::SetThreadCount(0);
            }

            ScopedThreadCount(const ScopedThreadCount &) = delete;
            ScopedThreadCount &operator=(const ScopedThreadCount &) = delete;
        };

        /**
        Runs parallel_apply on a detached thread and gives up after a deadline. A regression in
        parallel_apply's exception handling shows up as a livelock, which would hang the whole test
        binary instead of failing it; this turns that hang into a reported failure. The process is
        terminated on timeout because the wedged workers can never be joined, so even shutting down
        cleanly is impossible from that point on.
        */
        template <typename Func>
        ApplyOutcome apply_with_deadline(const PowersDag &pd, Func func)
        {
            auto outcome = make_shared<ApplyOutcome>();
            auto signal = make_shared<promise<void>>();
            future<void> done = signal->get_future();

            // NOLINTNEXTLINE(bugprone-exception-escape): both throwing calls below are guarded
            thread([pd, func, outcome, signal]() mutable {
                try {
                    pd.parallel_apply(func);
                } catch (...) {
                    // A thread function that lets anything escape terminates the process, so
                    // this catches every type, not only those derived from std::exception.
                    outcome->threw = true;
                }

                // The promise is fresh and satisfied once, so this cannot throw; it is guarded
                // for the same reason as above.
                try {
                    signal->set_value();
                } catch (...) { // NOLINT(bugprone-empty-catch)
                }
            }).detach();

            if (done.wait_for(chrono::seconds(30)) != future_status::ready) {
                ADD_FAILURE() << "parallel_apply did not return within 30 seconds; the thread pool "
                                 "is wedged";
                cout.flush();
                cerr.flush();
                _Exit(EXIT_FAILURE);
            }

            return *outcome;
        }
    } // namespace

    TEST(PowersTests, PowersDagRejectsUnreachableTargets)
    {
        // A target power that no two lower target powers sum to cannot be computed at all. The
        // search falls back on curr_power - 1 and 1, which is a real pair only when curr_power - 1
        // is itself a target power. configure has to reject the rest here: the alternative is a
        // node naming a parent that does not exist, which parallel_apply only discovers from
        // inside a worker thread.
        PowersDag pd;

        // 5 would need 1 + 4 or 2 + 3, and the set holds neither.
        ASSERT_FALSE(pd.configure({ 1 }, { 1, 5 }));
        ASSERT_FALSE(pd.is_configured());

        // Likewise 7, which is not the sum of two of 1, 2 and 3.
        ASSERT_FALSE(pd.configure({ 1, 2 }, { 1, 2, 3, 7 }));
        ASSERT_FALSE(pd.is_configured());

        // A rejected configuration leaves nothing of itself behind.
        ASSERT_THROW(static_cast<void>(pd.depth()), logic_error);
        ASSERT_THROW(static_cast<void>(pd.target_powers()), logic_error);

        // Filling in the missing powers makes both reachable.
        ASSERT_TRUE(pd.configure({ 1 }, { 1, 2, 3, 4, 5 }));
        ASSERT_TRUE(pd.is_configured());
        ASSERT_TRUE(pd.configure({ 1, 2 }, { 1, 2, 3, 4, 7 }));
        ASSERT_TRUE(pd.is_configured());

        // The fallback is a genuine decomposition for 2, whose only parents are 1 and 1.
        ASSERT_TRUE(pd.configure({ 1 }, { 1, 2 }));
        ASSERT_TRUE(pd.is_configured());
    }

    TEST(PowersTests, ParallelApply)
    {
        ScopedThreadCount threads(8);

        PowersDag pd;
        set<uint32_t> source_powers = { 1, 2, 5 };
        set<uint32_t> target_powers = create_powers_set(0, 64);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));

        vector<atomic<int>> visits(65);
        for (auto &visit : visits) {
            visit.store(0);
        }

        ApplyOutcome outcome = apply_with_deadline(
            pd, [&visits](const PowersDag::PowersNode &node) { visits[node.power]++; });

        ASSERT_FALSE(outcome.threw);
        for (uint32_t power = 1; power <= 64; power++) {
            ASSERT_EQ(1, visits[power].load()) << "power " << power << " was not visited once";
        }
    }

    TEST(PowersTests, ParallelApplyPropagatesException)
    {
        ScopedThreadCount threads(8);

        PowersDag pd;
        set<uint32_t> source_powers = { 1, 2, 5 };
        set<uint32_t> target_powers = create_powers_set(0, 64);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));

        // Throw on the highest target power. The abandoned node stays in the Computing state, so
        // the "all nodes computed" check can never pass again; before the fix, every other worker
        // kept re-scanning the node list at full speed and never returned.
        uint32_t poison = *target_powers.crbegin();

        ApplyOutcome outcome = apply_with_deadline(pd, [poison](const PowersDag::PowersNode &node) {
            if (node.power == poison) {
                throw runtime_error("poisoned node");
            }
        });

        ASSERT_TRUE(outcome.threw) << "the exception thrown by the applied function was swallowed";
    }

    TEST(PowersTests, ParallelApplyLeavesThreadPoolUsable)
    {
        ScopedThreadCount threads(8);

        // Hold a ThreadPoolMgr for the whole test, exactly as Sender::RunQuery does. This keeps
        // the shared pool alive across both calls below, which is what made the original livelock
        // permanent rather than confined to a single query.
        ThreadPoolMgr tpm;

        PowersDag pd;
        set<uint32_t> source_powers = { 1, 2, 5 };
        set<uint32_t> target_powers = create_powers_set(0, 64);
        ASSERT_TRUE(pd.configure(source_powers, target_powers));

        uint32_t poison = *target_powers.crbegin();
        ApplyOutcome failed_outcome =
            apply_with_deadline(pd, [poison](const PowersDag::PowersNode &node) {
                if (node.power == poison) {
                    throw runtime_error("poisoned node");
                }
            });
        ASSERT_TRUE(failed_outcome.threw);

        // The pool must still be able to run work: no worker may have been left spinning.
        vector<atomic<int>> visits(65);
        for (auto &visit : visits) {
            visit.store(0);
        }
        ApplyOutcome outcome = apply_with_deadline(
            pd, [&visits](const PowersDag::PowersNode &node) { visits[node.power]++; });

        ASSERT_FALSE(outcome.threw);
        for (uint32_t power = 1; power <= 64; power++) {
            ASSERT_EQ(1, visits[power].load()) << "power " << power << " was not visited once";
        }
    }
} // namespace APSITests
