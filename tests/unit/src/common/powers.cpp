// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <cstddef>
#include <numeric>
#include <sstream>
#include <set>

// APSI
#include "apsi/powers.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;

namespace APSITests
{
    TEST(PowersTests, PowersDagConfigure)
    {
        uint32_t seed = 123;

        PowersDag pd;
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(seed, 0, 0));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(seed, 0, 1));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(seed, 0, 1));
        ASSERT_FALSE(pd.is_configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(seed, 1, 0));
        ASSERT_FALSE(pd.is_configured());

        // Good configuration; required depth is 0
        ASSERT_TRUE(pd.configure(seed, 1, 1));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(1, pd.up_to_power());

        ASSERT_TRUE(pd.configure(seed, 2, 1));
        ASSERT_TRUE(pd.is_configured());
        ASSERT_EQ(1, pd.depth());

        // This should fail
        ASSERT_FALSE(pd.configure(seed, 60, 2));
        ASSERT_FALSE(pd.is_configured());

        // Check for member variables
        ASSERT_THROW(pd.depth(), logic_error);
        ASSERT_THROW(pd.source_count(), logic_error);
        ASSERT_THROW(pd.up_to_power(), logic_error);

        // Bad configuration
        ASSERT_FALSE(pd.configure(seed, 1, 0));
        ASSERT_FALSE(pd.is_configured());

        // Good configuration
        ASSERT_TRUE(pd.configure(seed, 1, 1));
        ASSERT_TRUE(pd.is_configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(1, pd.up_to_power());

        // Clear data
        pd.reset();
        ASSERT_FALSE(pd.is_configured());

        // Good configuration
        ASSERT_TRUE(pd.configure(seed, 20, 2));
        ASSERT_TRUE(pd.is_configured());
        ASSERT_EQ(4, pd.depth());
        ASSERT_EQ(2, pd.source_count());
        ASSERT_EQ(20, pd.up_to_power());

        // Good configuration
        ASSERT_TRUE(pd.configure(seed, 20, 3));
        ASSERT_TRUE(pd.is_configured());
        ASSERT_EQ(4, pd.depth());
        ASSERT_EQ(3, pd.source_count());
        ASSERT_EQ(20, pd.up_to_power());
    }

    TEST(PowersTest, Apply)
    {
        PowersDag pd;
        uint32_t seed = 123;
        pd.configure(seed, 20, 2);

        // Expected values
        vector<uint32_t> expected(20);
        iota(expected.begin(), expected.end(), 1);

        // Real results
        vector<uint32_t> real;
        pd.apply([&](auto &node) { real.push_back(node.power); });

        // Compare
        ASSERT_EQ(expected.size(), real.size());
        ASSERT_TRUE(equal(expected.begin(), expected.end(), real.begin()));
    }
}
