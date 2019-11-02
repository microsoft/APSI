// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdint>
#include "gtest/gtest.h"
#include "apsi/item.h"
#include "utils.h"

using namespace std;
using namespace apsi;


namespace APSITests
{
    TEST(ItemTests, constructor_test)
    {
        // Zero item test
        Item item;

        ASSERT_EQ(0ul, item[0]);
        ASSERT_EQ(0ul, item[1]);
    }

    TEST(ItemTests, parse_test)
    {
        // 128 bit string
        string input = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        Item item;

        item.parse(input, /* base */ 16);

        ASSERT_EQ((uint64_t)0xFFFFFFFFFFFFFFFF, item[0]);
        ASSERT_EQ((uint64_t)0xFFFFFFFFFFFFFFFF, item[1]);

        // One more nibble is out of range
        input = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

        ASSERT_ANY_THROW(item.parse(input, /* base */ 16));

        input = "80000000000000000000000000000001";
        item.parse(input, /* base */ 16);

        ASSERT_EQ((uint64_t)0x8000000000000000, item[1]);
        ASSERT_EQ((uint64_t)0x0000000000000001, item[0]);

        input = "FEDCBA9876543210";
        item.parse(input, /* base */ 16);

        ASSERT_EQ((uint64_t)0xFEDCBA9876543210, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        input = "abcdef";
        item.parse(input, /* base */ 16);

        ASSERT_EQ((uint64_t)0xABCDEF, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        input = "fedcba9876543210";
        item.parse(input, /* base */ 16);

        ASSERT_EQ((uint64_t)0xFEDCBA9876543210, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        input = "12345";
        item.parse(input, /* base */ 10);

        ASSERT_EQ((uint64_t)12345, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        input = "9223372036854775807";
        item.parse(input, /* base */ 10);

        ASSERT_EQ((uint64_t)0x7FFFFFFFFFFFFFFF, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        input = "2361200000000000000000";
        item.parse(input, /* base */ 10);

        ASSERT_EQ((uint64_t)0x003b89d384580000, item[0]);
        ASSERT_EQ((uint64_t)0x80, item[1]);
    }

    TEST(ItemTests, parse_empty_test)
    {
        string input = "";
        Item item;

        item.parse(input);

        ASSERT_EQ((uint64_t)0, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);
    }

    TEST(ItemTests, parse_diff_base_test)
    {
        Item item;

        // Base 8 not supported
        ASSERT_ANY_THROW(item.parse("12345", /* base */ 8));

        // Base 2 not supported
        ASSERT_ANY_THROW(item.parse("1010101010", /* base */ 2));
    }

    TEST(ItemTests, parse_non_regular_string_test)
    {
        Item item;

        item.parse("12345hello", /* base */ 10);

        // We should be able to parse until finding someting other than a number
        ASSERT_EQ((uint64_t)12345, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        item.parse("   45321   ", /* base */ 10);

        // Whitespace should be ignored
        ASSERT_EQ((uint64_t)45321, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        item.parse("800000000000000000000001ABCDG", /* base */ 16);

        ASSERT_EQ((uint64_t)0x1ABCD, item[0]);
        ASSERT_EQ((uint64_t)0x800000000000, item[1]);
    }

    TEST(ItemTests, parse_auto_detect_hex_test)
    {
        Item item;

        item.parse("  0xFFF ");

        ASSERT_EQ((uint64_t)0xFFF, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        item.parse("0XABCDEF");

        ASSERT_EQ((uint64_t)0xABCDEF, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);

        item.parse("   4566789abcdef");

        ASSERT_EQ((uint64_t)4566789, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);
    }
}
