// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <stdexcept>
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
        bytes.reserve(100);
        for (unsigned char i = 0; i < 100; i++) {
            bytes.push_back(i);
        }

        // Write the bytes to the stream
        ss.write(
            reinterpret_cast<const char *>(bytes.data()), static_cast<streamsize>(bytes.size()));

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
        bytes.reserve(size);
        for (uint32_t i = 0; i < size; i++) {
            bytes.push_back(static_cast<unsigned char>(i));
        }

        // Write the bytes to the stream
        ss.write(reinterpret_cast<const char *>(&size), sizeof(uint32_t));
        ss.write(
            reinterpret_cast<const char *>(bytes.data()), static_cast<streamsize>(bytes.size()));

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

        array<unsigned char, 5> arr1_5{ 0x1, 0x2, 0x1, 0x2, 0x1 };
        array<unsigned char, 5> arr2_5{ 0x2, 0x1, 0x2, 0x1, 0x2 };
        array<unsigned char, 5> res{ 0x3, 0x3, 0x3, 0x3, 0x3 };
        xor_buffers(arr1_5.data(), arr2_5.data(), arr1_5.size());
        ASSERT_TRUE(equal(arr1_5.begin(), arr1_5.end(), res.begin()));
    }

    TEST(UtilsTests, SecureRandomBytes)
    {
        // Every secret APSI generates comes from here, so check that it fills what it is asked
        // to fill and rejects the arguments it cannot honour.
        array<unsigned char, 64> buf{};
        ASSERT_NO_THROW(secure_random_bytes(buf.data(), buf.size()));

        // A filled buffer is not all zeros. This is a sanity check on the generator being wired
        // up at all, not a test of randomness quality.
        ASSERT_FALSE(all_of(buf.begin(), buf.end(), [](unsigned char b) { return b == 0; }));

        // Two draws differ. With 64 bytes a collision has probability 2^-512.
        array<unsigned char, 64> other{};
        secure_random_bytes(other.data(), other.size());
        ASSERT_FALSE(equal(buf.begin(), buf.end(), other.begin()));

        // Only the requested prefix is written.
        array<unsigned char, 8> partial{};
        secure_random_bytes(partial.data(), 4);
        ASSERT_TRUE(
            all_of(partial.begin() + 4, partial.end(), [](unsigned char b) { return b == 0; }));

        // Zero count is a no-op even with a null pointer, matching secure_zero.
        ASSERT_NO_THROW(secure_random_bytes(nullptr, 0));

        // A null buffer with a nonzero count is a caller error, not a silent no-op.
        ASSERT_THROW(secure_random_bytes(nullptr, 1), invalid_argument);

        // Any byte address is a valid destination and a request may be any length. An odd offset
        // is the case that breaks if the destination has to be aligned for the generator
        // underneath, and a length that is not a multiple of four exercises its final partial
        // word.
        array<unsigned char, 300> unaligned{};
        secure_random_bytes(unaligned.data() + 1, unaligned.size() - 2);
        ASSERT_EQ(0, unaligned.front());
        ASSERT_EQ(0, unaligned.back());
        ASSERT_FALSE(all_of(
            unaligned.begin() + 1, unaligned.end() - 1, [](unsigned char b) { return b == 0; }));
    }

    namespace {
        // Dirties a region of stack below its caller and records where. Must not be inlined:
        // the region has to be a real frame below the caller, where the scrub will later land.
        constexpr size_t stack_probe_byte_count = 8192;
        constexpr unsigned char stack_probe_pattern = 0xA5;

        // Where the dirtied region was. Recorded rather than returned so that no function
        // returns the address of its own local.
        volatile unsigned char *stack_probe_location = nullptr;

#ifdef _MSC_VER
        __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
        __attribute__((noinline))
#endif
        void dirty_stack_below_caller()
        {
            array<unsigned char, stack_probe_byte_count> buf{};
            volatile unsigned char *dirtied = buf.data();
            for (size_t i = 0; i < stack_probe_byte_count; i++) {
                dirtied[i] = stack_probe_pattern;
            }
            stack_probe_location = dirtied;
        }
    } // namespace

    TEST(UtilsTests, SecureZeroStack)
    {
        // A scrub whose buffer the compiler elided, or that someone shrank, would still link
        // and still be called with nothing to notice. Check that it writes zeros where a
        // previous call left data. Inspecting a frame that has been returned from is
        // platform-specific by nature, so the assertion is loose: most of the probed region, not
        // a byte-exact layout.
        volatile unsigned char *probe = nullptr;
        dirty_stack_below_caller();
        probe = stack_probe_location;
        ASSERT_NE(nullptr, probe);

        size_t dirty_before = 0;
        for (size_t i = 0; i < stack_probe_byte_count; i++) {
            if (probe[i] == stack_probe_pattern) {
                dirty_before++;
            }
        }
        // The probe must actually have left something behind, or the test proves nothing.
        ASSERT_GT(dirty_before, stack_probe_byte_count / 2);

        secure_zero_stack();

        size_t cleared = 0;
        for (size_t i = 0; i < stack_probe_byte_count; i++) {
            if (probe[i] == 0) {
                cleared++;
            }
        }
        // Demand most of the probe rather than half, so that a window shrunk to a fraction
        // fails. The probe is smaller than the window to leave room for layout differences.
        ASSERT_GT(cleared, (stack_probe_byte_count * 3) / 4);
    }
} // namespace APSITests
