// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <cstddef>
#include <numeric>
#include <sstream>
#include <set>

// APSI
#include "apsi/util/powers.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    TEST(PowersTests, PowersDagConfigure)
    {
        PowersDag pd;
        ASSERT_FALSE(pd.configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(0, 0, 0));
        ASSERT_FALSE(pd.configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(0, 0, 1));
        ASSERT_FALSE(pd.configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(0, 1, 1));
        ASSERT_FALSE(pd.configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(1, 0, 0));
        ASSERT_FALSE(pd.configured());

        // Good configuration; required depth is 0
        ASSERT_TRUE(pd.configure(1, 0, 1));
        ASSERT_TRUE(pd.configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(1, pd.up_to_power());

        // Bad configuration; required depth is 0
        ASSERT_FALSE(pd.configure(2, 0, 1));
        ASSERT_FALSE(pd.configured());

        // Check for member variables
        ASSERT_THROW(pd.depth(), logic_error);
        ASSERT_THROW(pd.source_count(), logic_error);
        ASSERT_THROW(pd.up_to_power(), logic_error);

        // Bad configuration
        ASSERT_FALSE(pd.configure(1, 1, 0));
        ASSERT_FALSE(pd.configured());

        // Good configuration
        ASSERT_TRUE(pd.configure(1, 1, 1));
        ASSERT_TRUE(pd.configured());

        // Check for member variables
        ASSERT_EQ(0, pd.depth());
        ASSERT_EQ(1, pd.source_count());
        ASSERT_EQ(1, pd.up_to_power());

        // Clear data
        pd.reset();
        ASSERT_FALSE(pd.configured());

        // Bad configuration
        ASSERT_FALSE(pd.configure(20, 2, 2));
        ASSERT_FALSE(pd.configured());

        // Good configuration
        ASSERT_TRUE(pd.configure(20, 3, 2));
        ASSERT_TRUE(pd.configured());
        ASSERT_EQ(3, pd.depth());
        ASSERT_EQ(2, pd.source_count());
        ASSERT_EQ(20, pd.up_to_power());

        // Good configuration
        ASSERT_TRUE(pd.configure(20, 2, 3));
        ASSERT_TRUE(pd.configured());
        ASSERT_EQ(2, pd.depth());
        ASSERT_EQ(3, pd.source_count());
        ASSERT_EQ(20, pd.up_to_power());
    }

    TEST(PowersTests, SaveLoadPowersDag)
    {
        auto save_load_compare = [](uint32_t up_to_power, uint32_t depth_bound, uint32_t source_count_bound)
        {
            PowersDag pd;
            pd.configure(up_to_power, depth_bound, source_count_bound);
            ASSERT_LE(pd.depth(), depth_bound);
            ASSERT_LE(pd.source_count(), source_count_bound);
            ASSERT_EQ(up_to_power, pd.up_to_power());

            stringstream ss;
            size_t sz = pd.save(ss);

            PowersDag pd2;
            size_t sz2 = pd2.load(ss);
            ASSERT_EQ(sz, sz2);

            ASSERT_EQ(pd.depth(), pd2.depth());
            ASSERT_EQ(pd.source_count(), pd2.source_count());
            ASSERT_EQ(pd.up_to_power(), pd2.up_to_power());

            // Compare the source nodes for pd and p2
            auto src = pd.source_nodes();
            set<uint32_t> src_powers;
            auto src2 = pd2.source_nodes();
            set<uint32_t> src2_powers;

            for (auto s : src)
            {
                src_powers.insert(s.power);
            }
            for (auto s : src2)
            {
                src2_powers.insert(s.power);
            }
            ASSERT_EQ(src_powers, src2_powers);
        };

        save_load_compare(1, 0, 1);
        save_load_compare(20, 2, 3);
    }

    TEST(PowersTest, OptimalPowers)
    {
        ASSERT_THROW(auto pd = optimal_powers(0, 0), invalid_argument);
        ASSERT_THROW(auto pd = optimal_powers(1, 0), invalid_argument);
        ASSERT_THROW(auto pd = optimal_powers(0, 1), invalid_argument);
        ASSERT_THROW(auto pd = optimal_powers(10, 11), invalid_argument);

        ASSERT_NO_THROW(auto pd = optimal_powers(10, 10));
        ASSERT_NO_THROW(auto pd = optimal_powers(10, 9));
        ASSERT_NO_THROW(auto pd = optimal_powers(10, 8));
        ASSERT_NO_THROW(auto pd = optimal_powers(10, 2));
        ASSERT_NO_THROW(auto pd = optimal_powers(10, 1));
    }

    TEST(PowersTest, Apply)
    {
        PowersDag pd;
        pd.configure(20, 3, 2);

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
