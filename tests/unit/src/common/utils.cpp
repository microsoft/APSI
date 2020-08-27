// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <vector>
#include <utility>
#include <cstdint>
#include <cstddef>
#include <sstream>

// APSI
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"

#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::util;

namespace APSITests
{
    namespace
    {
        void compare_up_to(const vector<seal_byte> &a, const vector<seal_byte> &b, size_t count)
        {
            for (size_t i = 0; i < count; i++)
            {
                ASSERT_EQ(static_cast<char>(a[i]), static_cast<char>(b[i]));
            }
        }
    }

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
        auto compare_results = [](auto &&in1, auto &&in2) -> bool {
            if (in1.size() != in2.size())
            {
                return false;
            }
            for (size_t i = 0; i < in1.size(); i++)
            {
                if (in1[i].first != in2[i].first || in1[i].second != in2[i].second)
                {
                    return false;
                }
            }
            return true;
        };

        vector<pair<size_t, size_t>> compare;

        auto res = partition_evenly(0, 0);
        compare = {};
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(0, 1);
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(0, 2);
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(1, 1);
        compare = { make_pair(0, 1) };
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(1, 2);
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(5, 1);
        compare = { make_pair(0, 5) };
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(5, 2);
        compare = { make_pair(0, 3), make_pair(3, 5) };
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(5, 3);
        compare = { make_pair(0, 2), make_pair(2, 4), make_pair(4, 5) };
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(5, 4);
        compare = { make_pair(0, 2), make_pair(2, 3), make_pair(3, 4), make_pair(4, 5) };
        ASSERT_TRUE(compare_results(res, compare));

        res = partition_evenly(5, 5);
        compare = { make_pair(0, 1), make_pair(1, 2), make_pair(2, 3), make_pair(3, 4), make_pair(4, 5) };
        ASSERT_TRUE(compare_results(res, compare));

        // More partitions than values; only create up to the number of values many partitions, each of size one
        res = partition_evenly(5, 6);
        ASSERT_TRUE(compare_results(res, compare));
    }

    TEST(UtilsTests, ReadFromStream)
    {
        stringstream ss;
        vector<seal_byte> bytes;
        for (size_t i = 0; i < 100; i++)
        {
            bytes.push_back(static_cast<seal_byte>(i));
        }

        // Write the bytes to the stream
        ss.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());

        // Now read them back to a different vector
        vector<seal_byte> compare;

        // Read nothing
        read_from_stream(ss, 0, compare);
        ASSERT_EQ(0, compare.size());

        // Read one byte
        read_from_stream(ss, 1, compare);
        ASSERT_EQ(1, compare.size());
        compare_up_to(compare, bytes, 1);

        // Read two bytes
        read_from_stream(ss, 2, compare);
        ASSERT_EQ(3, compare.size());
        compare_up_to(compare, bytes, 3);

        // Read three bytes
        read_from_stream(ss, 3, compare);
        ASSERT_EQ(6, compare.size());
        compare_up_to(compare, bytes, 6);

        // Read the rest
        read_from_stream(ss, bytes.size() - 6, compare);
        ASSERT_EQ(bytes.size(), compare.size());
        compare_up_to(compare, bytes, bytes.size());
    }

    TEST(UtilsTests, ReadFromStreamSizePrefixed)
    {
        stringstream ss;
        vector<seal_byte> bytes;

        uint32_t size = 100;
        for (uint32_t i = 0; i < size; i++)
        {
            bytes.push_back(static_cast<seal_byte>(i));
        }

        // Write the bytes to the stream
        ss.write(reinterpret_cast<const char*>(&size), sizeof(uint32_t));
        ss.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());

        // Now read them back to a different vector
        vector<seal_byte> compare = read_from_stream(ss);

        // The result contains the size prefix and the rest of the data will match
        ASSERT_EQ(compare.size() - sizeof(uint32_t), bytes.size());
        compare.erase(compare.begin(), compare.begin() + sizeof(uint32_t));
        compare_up_to(compare, bytes, bytes.size());
    }
} // namespace APSITests
