// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstdint>
#include <random>
#include <stdexcept>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/util/db_encoding.h"

// SEAL
#include "seal/util/defines.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;
using namespace seal;

namespace APSITests {
    namespace {
        felt_t get_bit(const vector<unsigned char> &in, size_t bit_idx)
        {
            size_t byte_idx = bit_idx >> 3;
            felt_t res = static_cast<felt_t>(in[byte_idx]);
            size_t bit_in_byte = bit_idx - (byte_idx * 8);
            return (res >> bit_in_byte) & 0x1;
        }

        felt_t get_nibble(const vector<unsigned char> &in, size_t nibble_idx)
        {
            size_t byte_idx = nibble_idx >> 1;
            felt_t res = static_cast<felt_t>(in[byte_idx]);
            size_t nibble_in_byte = nibble_idx - (byte_idx * 2);
            return (res >> (nibble_in_byte * 4)) & 0xF;
        }
    } // namespace

    TEST(DbEncodingTests, BitsToFieldElts)
    {
        vector<unsigned char> data(4);
        data[0] = 0xF;
        data[1] = 0x1F;
        data[2] = 0x0F;
        data[3] = 0x1F;

        BitstringView<const unsigned char> bsv(
            { data.data(), data.size() }, static_cast<uint32_t>(8 * data.size()));

        // Modulus 3 should cause every bit to be extracted separately
        Modulus mod = 3;
        vector<felt_t> felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(8 * data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++) {
            ASSERT_EQ(get_bit(data, idx), felts[idx]);
        }

        // Convert back
        Bitstring back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++) {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // A 5-bit modulus should cause every nibble to be extracted separately
        mod = 1 << 4;
        felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(2 * data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++) {
            ASSERT_EQ(get_nibble(data, idx), felts[idx]);
        }

        // Convert back
        back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++) {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // A 9-bit modulus should cause every byte to be extracted separately
        mod = 1 << 8;
        felts = bits_to_field_elts(bsv, mod);
        ASSERT_EQ(data.size(), felts.size());
        for (size_t idx = 0; idx < felts.size(); idx++) {
            ASSERT_EQ(static_cast<felt_t>(data[idx]), felts[idx]);
        }

        // Convert back
        back_bs = field_elts_to_bits(felts, bsv.bit_count(), mod);
        ASSERT_EQ(bsv.bit_count(), back_bs.bit_count());
        ASSERT_EQ(bsv.data().size(), back_bs.data().size());
        for (size_t idx = 0; idx < back_bs.data().size(); idx++) {
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
        for (size_t idx = 0; idx < back_bs.data().size(); idx++) {
            ASSERT_EQ(bsv.data()[idx], back_bs.data()[idx]);
        }

        // Modulus 0 is not allowed
        // Modulus 1 would not make sense, but SEAL Modulus cannot be 1
        mod = 0;
        ASSERT_THROW(felts = bits_to_field_elts(bsv, mod), invalid_argument);

        // An input of size 0 is not allowed when converting from felts to bits
        mod = 3;
        ASSERT_THROW(back_bs = field_elts_to_bits({}, 0, mod), invalid_argument);
    }

    TEST(DbEncodingTests, BitsToFieldEltsRoundTrip)
    {
        // Tests that encoding bitstring -> field elements -> bitstring is a lossless round trip
        for (int rep = 0; rep < 20; rep++) {
            // Make a SEAL modulus. This defines our field.
            Modulus mod(0x51F2);

            // Make a random bitstring
            random_device rd;
            vector<unsigned char> bytes(256);
            std::generate(
                begin(bytes), end(bytes), [&] { return static_cast<unsigned char>(rd()); });

            // Pick a random bit length within range, i.e., within 7 bits of the total length
            std::uniform_int_distribution<size_t> bitlen_dist(0, 7);
            size_t bitlen_diff = bitlen_dist(rd);
            uint32_t bit_len = static_cast<uint32_t>((bytes.size() * 8) - bitlen_diff);

            // Mask away extra bits from top byte
            bytes.back() &= static_cast<unsigned char>((1 << (8 - bitlen_diff)) - 1);

            // Make the Bitstring object
            Bitstring bs(std::move(bytes), bit_len);

            // Now do a round trip
            vector<felt_t> felts = bits_to_field_elts(bs.to_view(), mod);
            Bitstring back_bs = field_elts_to_bits(felts, bit_len, mod);

            // Make sure that the round trip is the identity
            ASSERT_EQ(bs.bit_count(), back_bs.bit_count());
            ASSERT_EQ(bs.data().size(), back_bs.data().size());
            for (size_t idx = 0; idx < bs.data().size(); idx++) {
                ASSERT_EQ(
                    static_cast<char>(bs.data()[idx]), static_cast<char>(back_bs.data()[idx]));
            }
        }
    }

    TEST(DbEncodingTests, AlgebraizeItemTagLabel)
    {
        Modulus mod(65537);
        HashedItem item(0x0123456789abcdefULL, 0xfedcba9876543210ULL);

        // Two field elements of 16 bits per item and a tag of three parts, in the part-major
        // layout of compute_match_tag: part p in slot s is tag[p * 2 + s]
        size_t item_bit_count = 32;
        size_t felts_per_item = 2;
        size_t tag_part_count = 3;
        vector<felt_t> tag{ 11, 12, 21, 22, 31, 32 };
        AlgItem alg_item = algebraize_item(item, item_bit_count, mod);
        ASSERT_EQ(felts_per_item, alg_item.size());

        // Without a label, the label parts are the tag parts alone
        AlgItemLabel unlabeled = algebraize_item_tag_label(item, tag, {}, item_bit_count, mod);
        ASSERT_EQ(felts_per_item, unlabeled.size());
        for (size_t s = 0; s < felts_per_item; s++) {
            ASSERT_EQ(alg_item[s], unlabeled[s].first);
            ASSERT_EQ(tag_part_count, unlabeled[s].second.size());
            for (size_t p = 0; p < tag_part_count; p++) {
                ASSERT_EQ(tag[(p * felts_per_item) + s], unlabeled[s].second[p]);
            }
        }

        // With one, the parts of the label follow the tag parts, exactly as algebraize_item_label
        // lays them out
        for (size_t label_byte_count : { 1U, 4U, 5U, 13U }) {
            EncryptedLabel label(label_byte_count);
            for (size_t i = 0; i < label_byte_count; i++) {
                label[i] = static_cast<unsigned char>(0x5a + 17 * i);
            }
            AlgItemLabel expected_label = algebraize_item_label(item, label, item_bit_count, mod);
            AlgItemLabel labeled = algebraize_item_tag_label(item, tag, label, item_bit_count, mod);
            ASSERT_EQ(felts_per_item, labeled.size());
            for (size_t s = 0; s < felts_per_item; s++) {
                ASSERT_EQ(alg_item[s], labeled[s].first);
                size_t label_part_count = expected_label[s].second.size();
                ASSERT_EQ(tag_part_count + label_part_count, labeled[s].second.size());
                for (size_t p = 0; p < tag_part_count; p++) {
                    ASSERT_EQ(tag[(p * felts_per_item) + s], labeled[s].second[p]);
                }
                for (size_t p = 0; p < label_part_count; p++) {
                    ASSERT_EQ(expected_label[s].second[p], labeled[s].second[tag_part_count + p]);
                }
            }
        }

        // The tag must have a whole number of parts, and at least one
        ASSERT_THROW(
            algebraize_item_tag_label(item, {}, {}, item_bit_count, mod), invalid_argument);
        vector<felt_t> ragged_tag{ 1, 2, 3 };
        ASSERT_THROW(
            algebraize_item_tag_label(item, ragged_tag, {}, item_bit_count, mod), invalid_argument);

        // One field element per item takes a tag of any length
        AlgItemLabel one_felt = algebraize_item_tag_label(item, ragged_tag, {}, 16, mod);
        ASSERT_EQ(1, one_felt.size());
        ASSERT_EQ(ragged_tag, one_felt[0].second);
    }
} // namespace APSITests
