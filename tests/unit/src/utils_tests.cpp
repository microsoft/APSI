// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <vector>
#include "apsi/tools/utils.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;

namespace APSITests
{
    TEST(UtilsTests, conversion_to_digits_test)
    {
        u64 number = 1234;
        vector<u64> digits = conversion_to_digits(number, /* base */ 10);

        ASSERT_EQ((size_t)4, digits.size());
        ASSERT_EQ((u64)1, digits[3]);
        ASSERT_EQ((u64)2, digits[2]);
        ASSERT_EQ((u64)3, digits[1]);
        ASSERT_EQ((u64)4, digits[0]);

        digits = conversion_to_digits(number, /* base */ 16);

        ASSERT_EQ((size_t)3, digits.size());
        ASSERT_EQ((u64)0x4, digits[2]);
        ASSERT_EQ((u64)0xd, digits[1]);
        ASSERT_EQ((u64)0x2, digits[0]);

        digits = conversion_to_digits(number, /* base */ 8);

        ASSERT_EQ((size_t)4, digits.size());
        ASSERT_EQ((u64)2, digits[3]);
        ASSERT_EQ((u64)3, digits[2]);
        ASSERT_EQ((u64)2, digits[1]);
        ASSERT_EQ((u64)2, digits[0]);
    }
} // namespace APSITests
