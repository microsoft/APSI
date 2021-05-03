// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <utility>
#include <vector>

// APSI
#include "apsi/util/utils.h"

// SEAL
#include "seal/util/defines.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::util;

namespace APSITests {
    namespace {
        template <typename T>
        void compare_up_to(const vector<T> &a, const vector<T> &b, size_t count)
        {
            for (size_t i = 0; i < count; i++) {
                ASSERT_EQ(a[i], b[i]);
            }
        }
    } // namespace

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
            if (in1.size() != in2.size()) {
                return false;
            }
            for (size_t i = 0; i < in1.size(); i++) {
                if (in1[i].first != in2[i].first || in1[i].second != in2[i].second) {
                    return false;
                }
            }
            return true;
        };

        vector<pair<int, int>> compare;

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
        compare = {
            make_pair(0, 1), make_pair(1, 2), make_pair(2, 3), make_pair(3, 4), make_pair(4, 5)
        };
        ASSERT_TRUE(compare_results(res, compare));

        // More partitions than values; only create up to the number of values many partitions, each
        // of size one
        res = partition_evenly(5, 6);
        ASSERT_TRUE(compare_results(res, compare));
    }

    TEST(UtilsTests, ReadFromStream)
    {
        stringstream ss;
        vector<unsigned char> bytes;
        for (unsigned char i = 0; i < 100; i++) {
            bytes.push_back(i);
        }

        // Write the bytes to the stream
        ss.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());

        // Now read them back to a different vector
        vector<unsigned char> compare;

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
        read_from_stream(ss, static_cast<uint32_t>(bytes.size() - 6), compare);
        ASSERT_EQ(bytes.size(), compare.size());
        compare_up_to(compare, bytes, bytes.size());
    }

    TEST(UtilsTests, ReadFromStreamSizePrefixed)
    {
        stringstream ss;
        vector<unsigned char> bytes;

        uint32_t size = 100;
        for (uint32_t i = 0; i < size; i++) {
            bytes.push_back(static_cast<unsigned char>(i));
        }

        // Write the bytes to the stream
        ss.write(reinterpret_cast<const char *>(&size), sizeof(uint32_t));
        ss.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());

        // Now read them back to a different vector
        vector<unsigned char> compare = read_from_stream(ss);

        // The result contains the size prefix and the rest of the data will match
        ASSERT_EQ(compare.size() - sizeof(uint32_t), bytes.size());
        compare.erase(compare.begin(), compare.begin() + sizeof(uint32_t));
        compare_up_to(compare, bytes, bytes.size());
    }

    TEST(UtilsTests, XorBuffers)
    {
        uint32_t val1 = 0;
        uint32_t val2 = 0;
        xor_buffers(
            reinterpret_cast<unsigned char *>(&val1),
            reinterpret_cast<const unsigned char *>(&val2),
            sizeof(uint32_t));
        ASSERT_EQ(0, val1);

        val1 = 0xABABABAB;
        val2 = 0xABABABAB;
        xor_buffers(
            reinterpret_cast<unsigned char *>(&val1),
            reinterpret_cast<const unsigned char *>(&val2),
            sizeof(uint32_t));
        ASSERT_EQ(0, val1);

        val1 = 0xAAAAAAAA;
        val2 = 0x55555555;
        xor_buffers(
            reinterpret_cast<unsigned char *>(&val1),
            reinterpret_cast<const unsigned char *>(&val2),
            sizeof(uint32_t));
        ASSERT_EQ(0xFFFFFFFF, val1);

        val1 = 0xAAAAAAAA >> 1;
        val2 = 0x55555555;
        xor_buffers(
            reinterpret_cast<unsigned char *>(&val1),
            reinterpret_cast<const unsigned char *>(&val2),
            sizeof(uint32_t));
        ASSERT_EQ(0, val1);

        unsigned char arr1_5[5]{ 0x1, 0x2, 0x1, 0x2, 0x1 };
        unsigned char arr2_5[5]{ 0x2, 0x1, 0x2, 0x1, 0x2 };
        unsigned char res[5]{ 0x3, 0x3, 0x3, 0x3, 0x3 };
        xor_buffers(arr1_5, arr2_5, sizeof(arr1_5));
        ASSERT_TRUE(equal(arr1_5, arr1_5 + sizeof(arr1_5), res));
    }
} // namespace APSITests
