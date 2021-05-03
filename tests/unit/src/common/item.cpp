// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <array>
#include <cstdint>
#include <numeric>

// APSI
#include "apsi/item.h"

// SEAL
#include "seal/util/defines.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace seal;

namespace APSITests {
    TEST(BitstringViewTests, Basics)
    {
        array<unsigned char, 8> data = {};
        for (size_t i = 0; i < data.size(); i++) {
            data[i] = static_cast<unsigned char>(i);
        }

        // BitstringView to a single byte
        unsigned char sb{ 0xA5 };
        BitstringView<unsigned char> bsv(gsl::span<unsigned char>(&sb, 1), 1);
        ASSERT_EQ(bsv.bit_count(), 1);
        ASSERT_EQ(bsv.data().size(), 1);
        ASSERT_EQ(static_cast<char>(sb), static_cast<char>(bsv.data()[0]));

        // Use all bits in the buffer
        bsv = BitstringView<unsigned char>(data, 64);
        ASSERT_EQ(bsv.bit_count(), 64);
        ASSERT_EQ(bsv.data().size(), 8);
        ASSERT_EQ(data.data(), bsv.data().data());

        // Use as few bits as possible but same number of bytes as buffer
        bsv = BitstringView<unsigned char>(data, 57);
        ASSERT_EQ(bsv.bit_count(), 57);
        ASSERT_EQ(bsv.data().size(), 8);
        ASSERT_EQ(data.data(), bsv.data().data());

        bsv = BitstringView<unsigned char>(data, 56);
        ASSERT_EQ(bsv.bit_count(), 56);
        ASSERT_EQ(bsv.data().size(), 7);
        ASSERT_EQ(data.data(), bsv.data().data());

        // Corner-cases
        ASSERT_THROW(bsv = BitstringView<unsigned char>(data, 0), invalid_argument);
        ASSERT_THROW(bsv = BitstringView<unsigned char>(data, 65), invalid_argument);
    }

    TEST(BitstringTests, Basics)
    {
        auto get_data = []() {
            vector<unsigned char> data(8, 0);
            for (size_t i = 0; i < data.size(); i++) {
                data[i] = static_cast<unsigned char>(i);
            }
            return data;
        };

        auto get_single_byte = []() {
            vector<unsigned char> single_byte;
            single_byte.push_back(0xA5);
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
        ASSERT_THROW(bs = Bitstring(get_data(), 0), invalid_argument);
        ASSERT_THROW(bs = Bitstring(get_data(), 65), invalid_argument);
        // ASSERT_THROW(Bitstring bs(get_data(), 56), invalid_argument);

        bs = Bitstring(get_data(), 56);
        ASSERT_EQ(bs.bit_count(), 56);
        ASSERT_EQ(bs.data().size(), 7);
    }

    TEST(ItemTests, Constructor)
    {
        // Zero item test
        Item item;

        auto data = item.get_as<uint64_t>();
        ASSERT_EQ(uint64_t(0), data[0]);
        ASSERT_EQ(uint64_t(0), data[1]);

        // Size must be 16 bytes
        ASSERT_EQ(size_t(16), sizeof(Item));

        Item item2(0xFAFAFAFAFAFAFAFAULL, 0xB0B0B0B0B0B0B0B0ULL);
        auto data2 = item2.get_as<uint64_t>();
        ASSERT_EQ(0xFAFAFAFAFAFAFAFAULL, data2[0]);
        ASSERT_EQ(0xB0B0B0B0B0B0B0B0ULL, data2[1]);
    }
} // namespace APSITests
