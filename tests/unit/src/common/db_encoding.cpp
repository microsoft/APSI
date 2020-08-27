// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <random>
#include <vector>
#include <stdexcept>

// APSI
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/util/defines.h"

#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;
using namespace seal;

namespace APSITests
{
    namespace
    {
        felt_t get_bit(const vector<seal_byte> &in, size_t bit_idx)
        {
            size_t byte_idx = bit_idx >> 3;
            felt_t res = static_cast<felt_t>(in[byte_idx]);
            size_t bit_in_byte = bit_idx - byte_idx * 8;
            return (res >> bit_in_byte) & 0x1;
        }

        felt_t get_nibble(const vector<seal_byte> &in, size_t nibble_idx)
        {
            size_t byte_idx = nibble_idx >> 1;
            felt_t res = static_cast<felt_t>(in[byte_idx]);
            size_t nibble_in_byte = nibble_idx - byte_idx * 2;
            return (res >> (nibble_in_byte * 4)) & 0xF;
        }
    }

    TEST(DbEncodingTests, BitsToFieldElts)
    {
        vector<seal_byte> data(4);
        data[0] = seal_byte(0xF);
        data[1] = seal_byte(0x1F);
        data[2] = seal_byte(0x0F);
        data[3] = seal_byte(0x1F);

        BitstringView<const seal_byte> bsv({ data.data(), data.size() }, 8 * data.size());

        // Modulus 3 should cause every bit to be extracted separately
        Modulus mod = 3;
        vector<felt_t> felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(8 * data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++)
        {
            ASSERT_EQ(get_bit(data, idx), felts[idx]);
        }

        // Convert back
        Bitstring back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++)
        {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // A 5-bit modulus should cause every nibble to be extracted separately
        mod = 1 << 4;
        felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(2 * data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++)
        {
            ASSERT_EQ(get_nibble(data, idx), felts[idx]);
        }

        // Convert back
        back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++)
        {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // A 9-bit modulus should cause every byte to be extracted separately
        mod = 1 << 8;
        felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++)
        {
            ASSERT_EQ(static_cast<felt_t>(data[idx]), felts[idx]);
        }

        // Convert back
        back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++)
        {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // A 13-bit modulus
        mod = 1 << 13;
        felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(size_t(3), felts.size());
        ASSERT_EQ(felt_t(0x1F0F), felts[0]);
        ASSERT_EQ(felt_t(0x1878), felts[1]);
        ASSERT_EQ(felt_t(0x7), felts[2]);

        // Convert back
        back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++)
        {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // Modulus 0 is not allowed
        // Modulus 1 would not make sense, but SEAL Modulus cannot be 1
        mod = 0;
        ASSERT_THROW(felts = bits_to_field_elts(bsv, mod), invalid_argument);

        // An input of size 0 is not allowed when converting from felts to bits 
        mod = 3;
        ASSERT_THROW(back_bs = field_elts_to_bits({ }, 0, mod), invalid_argument);
    }

    TEST(DbEncodingTests, BitsToFieldEltsRoundTrip)
    {
        // Tests that encoding bitstring -> field elements -> bitstring is a lossless round trip
        for (int rep = 0; rep < 20; rep++)
        {
            // Make a SEAL modulus. This defines our field.
            Modulus mod(0x51F2);

            // Make a random bitstring
            random_device rd;
            vector<seal_byte> bytes(256);
            std::generate(begin(bytes), end(bytes), [&]() { return static_cast<seal_byte>(rd()); });

            // Pick a random bit length within range, i.e., within 7 bits of the total length
            std::uniform_int_distribution<size_t> bitlen_dist(0, 7);
            size_t bitlen_diff = bitlen_dist(rd);
            size_t bit_len = bytes.size() * 8 - bitlen_diff;

            // Mask away extra bits from top byte
            bytes.back() &= static_cast<seal_byte>((1 << (8 - bitlen_diff)) - 1);

            // Make the Bitstring object
            Bitstring bs(move(bytes), bit_len);

            // Now do a round trip
            vector<felt_t> felts = bits_to_field_elts(bs.to_view(), mod);
            Bitstring back_bs = field_elts_to_bits(felts, bit_len, mod);

            // Make sure that the round trip is the identity
            ASSERT_EQ(bs.bit_count(), back_bs.bit_count());
            ASSERT_EQ(bs.data().size(), back_bs.data().size());
            for (size_t idx = 0; idx < bs.data().size(); idx++)
            {
                ASSERT_EQ(static_cast<char>(bs.data()[idx]), static_cast<char>(back_bs.data()[idx]));
            }
        }
    }
} // namespace APSITests
