// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <vector>
#include "apsi/util/utils.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    TEST(UtilsTests, conversion_to_digits_test)
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
} // namespace APSITests
