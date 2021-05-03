// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <set>
#include <sstream>

// APSI
#include "apsi/powers.h"
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
        ASSERT_THROW(pd.depth(), logic_error);
        ASSERT_THROW(pd.source_count(), logic_error);
        ASSERT_THROW(pd.target_powers(), logic_error);

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
} // namespace APSITests
