// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <array>
#include <numeric>

// APSI
#include "apsi/item.h"

// SEAL
#include "seal/util/defines.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace seal;

namespace APSITests
{
    TEST(BitstringViewTests, Basics)
    {
        array<SEAL_BYTE, 8> data = {};
        for (size_t i = 0; i < data.size(); i++)
        {
            data[i] = static_cast<SEAL_BYTE>(i);
        }

        // BitstringView to a single byte
        SEAL_BYTE sb{ 0xA5 };
        BitstringView<SEAL_BYTE> bsv(gsl::span<SEAL_BYTE>(&sb, 1), 1);
        ASSERT_EQ(bsv.bit_count(), 1);
        ASSERT_EQ(bsv.data().size(), 1);
        ASSERT_EQ(static_cast<char>(sb), static_cast<char>(bsv.data()[0]));

        // Use all bits in the buffer
        bsv = BitstringView<SEAL_BYTE>(data, 64);
        ASSERT_EQ(bsv.bit_count(), 64);
        ASSERT_EQ(bsv.data().size(), 8);
        ASSERT_EQ(data.data(), bsv.data().data());

        // Use as few bits as possible but same number of bytes as buffer
        bsv = BitstringView<SEAL_BYTE>(data, 57);
        ASSERT_EQ(bsv.bit_count(), 57);
        ASSERT_EQ(bsv.data().size(), 8);
        ASSERT_EQ(data.data(), bsv.data().data());

        // Corner-cases
        ASSERT_THROW(BitstringView<SEAL_BYTE> bsv(data, 0), invalid_argument);
        ASSERT_THROW(BitstringView<SEAL_BYTE> bsv(data, 65), invalid_argument);
        ASSERT_THROW(BitstringView<SEAL_BYTE> bsv(data, 56), invalid_argument);
    }

    TEST(BitstringTests, Basics)
    {
        auto get_data = []() {
            vector<SEAL_BYTE> data(8, SEAL_BYTE(0));
            for (size_t i = 0; i < data.size(); i++)
            {
                data[i] = static_cast<SEAL_BYTE>(i);
            }
            return data;
        };

        auto get_single_byte = []() {
            vector<SEAL_BYTE> single_byte;
            single_byte.push_back(SEAL_BYTE(0xA5));
            return single_byte;
        };

        // BitstringView to a single byte
        Bitstring bs(get_single_byte(), 1);
        ASSERT_EQ(bs.bit_count(), 1);
        ASSERT_EQ(bs.data().size(), 1);
        ASSERT_EQ(static_cast<char>(get_single_byte()[0]), static_cast<char>(bs.data()[0]));

        // Use all bits in the buffer
        ASSERT_EQ(8, get_data().size());
        bs = Bitstring(get_data(), 64);
        ASSERT_EQ(bs.bit_count(), 64);
        ASSERT_EQ(bs.data().size(), 8);

        // Use as few bits as possible but same number of bytes as buffer
        bs = Bitstring(get_data(), 57);
        ASSERT_EQ(bs.bit_count(), 57);
        ASSERT_EQ(bs.data().size(), 8);

        // Corner-cases
        ASSERT_THROW(Bitstring bs(get_data(), 0), invalid_argument);
        ASSERT_THROW(Bitstring bs(get_data(), 65), invalid_argument);
        ASSERT_THROW(Bitstring bs(get_data(), 56), invalid_argument);
    }

    TEST(ItemTests, Constructor)
    {
        // Zero item test
        Item item;

        ASSERT_EQ(uint64_t(0), item[0]);
        ASSERT_EQ(uint64_t(0), item[1]);

        // Size must be 16 bytes
        ASSERT_EQ(size_t(16), sizeof(Item));
    }

    TEST(ItemTests, Parse)
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

    TEST(ItemTests, ParseEmpty)
    {
        string input = "";
        Item item;

        item.parse(input);

        ASSERT_EQ((uint64_t)0, item[0]);
        ASSERT_EQ((uint64_t)0, item[1]);
    }

    TEST(ItemTests, ParseDiffBase)
    {
        Item item;

        // Base 8 not supported
        ASSERT_ANY_THROW(item.parse("12345", /* base */ 8));

        // Base 2 not supported
        ASSERT_ANY_THROW(item.parse("1010101010", /* base */ 2));
    }

    TEST(ItemTests, ParseNonRegularString)
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

    TEST(ItemTests, ParseAutoDetectHex)
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
} // namespace APSITests
