// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <vector>
#include <utility>
#include "apsi/util/utils.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    TEST(UtilsTests, ConversionToDigits)
    {
        uint64_t number = 1234;
        vector<uint64_t> digits = conversion_to_digits(number, /* base */ 10);

        ASSERT_EQ((size_t)4, digits.size());
        ASSERT_EQ((uint64_t)1, digits[3]);
        ASSERT_EQ((uint64_t)2, digits[2]);
        ASSERT_EQ((uint64_t)3, digits[1]);
        ASSERT_EQ((uint64_t)4, digits[0]);

        digits = conversion_to_digits(number, /* base */ 16);

        ASSERT_EQ((size_t)3, digits.size());
        ASSERT_EQ((uint64_t)0x4, digits[2]);
        ASSERT_EQ((uint64_t)0xd, digits[1]);
        ASSERT_EQ((uint64_t)0x2, digits[0]);

        digits = conversion_to_digits(number, /* base */ 8);

        ASSERT_EQ((size_t)4, digits.size());
        ASSERT_EQ((uint64_t)2, digits[3]);
        ASSERT_EQ((uint64_t)3, digits[2]);
        ASSERT_EQ((uint64_t)2, digits[1]);
        ASSERT_EQ((uint64_t)2, digits[0]);
    }

    TEST(UtilsTests, PartitionEvenly)
    {
        auto res = partition_evenly(0, 0);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{}));

        res = partition_evenly(0, 1);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{}));

        res = partition_evenly(0, 2);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{}));

        res = partition_evenly(1, 1);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 1} }));

        res = partition_evenly(1, 2);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 1} }));

        res = partition_evenly(5, 1);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 5} }));

        res = partition_evenly(5, 2);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 3}, {3, 5} }));

        res = partition_evenly(5, 3);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 2}, {2, 4}, {4, 5} }));

        res = partition_evenly(5, 4);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 2}, {2, 3}, {3, 4}, {4, 5} }));

        res = partition_evenly(5, 5);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 5} }));

        res = partition_evenly(5, 6);
        ASSERT_TRUE((res == vector<pair<size_t, size_t>>{ {0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 5} }));
    }
} // namespace APSITests
