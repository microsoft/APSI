// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// APSI
#include "apsi/item.h"
#include "apsi/util/db_encoding.h"
#include "apsi/util/label_encryptor.h"
#include "apsi/util/match_tag.h"

// SEAL
#include "seal/modulus.h"
#include "seal/util/blake2.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::util;
using namespace seal;

namespace APSITests {
    namespace {
        LabelKey sequential_key()
        {
            LabelKey key{};
            for (size_t i = 0; i < key.size(); i++) {
                key[i] = static_cast<unsigned char>(i);
            }
            return key;
        }

        /**
        The Blake2xb output a tag of the given size is read from.
        */
        vector<unsigned char> tag_stream(const LabelKey &key, size_t felt_count, uint32_t b)
        {
            vector<unsigned char> bytes(((felt_count * b) + 7) / 8);
            if (blake2xb(
                    bytes.data(),
                    bytes.size(),
                    match_tag_domain.data(),
                    match_tag_domain.size(),
                    key.data(),
                    key.size()) != 0) {
                throw runtime_error("blake2xb failed");
            }
            return bytes;
        }
    } // namespace

    TEST(MatchTagTests, KnownAnswers)
    {
        // These were computed outside APSI, by an implementation of BLAKE2b written from RFC 7693
        // and of BLAKE2Xb written from the BLAKE2X specification, which shares no code with the
        // one in Microsoft SEAL that APSI calls, followed by the bit layout of
        // compute_match_tag: the output read as a little-endian integer, bits j * b up to
        // (j + 1) * b forming field element j. A change to any of them changes these values, and
        // makes every tag a deployed sender stores disagree with the receivers that check it.
        LabelKey key = sequential_key();

        ASSERT_EQ((vector<felt_t>{ 51959, 24820, 51291 }), compute_match_tag(key, 3, 16));
        ASSERT_EQ((vector<felt_t>{ 6174, 1878, 5499, 3544 }), compute_match_tag(key, 4, 13));
        ASSERT_EQ(
            (vector<felt_t>{ 102757, 983209, 1763483, 1120139, 1812453 }),
            compute_match_tag(key, 5, 21));
        ASSERT_EQ((vector<felt_t>{ 687974, 580976 }), compute_match_tag(key, 2, 20));
        ASSERT_EQ(
            (vector<felt_t>{ 1916, 10, 3380, 4893, 6395, 498, 6407 }),
            compute_match_tag(key, 7, 13));

        LabelKey other_key{};
        other_key.fill(0xA5);
        ASSERT_EQ((vector<felt_t>{ 19628, 52816, 41907 }), compute_match_tag(other_key, 3, 16));

        // The Blake2xb output itself, for two of them
        ASSERT_EQ(
            (vector<unsigned char>{ 0xF7, 0xCA, 0xF4, 0x60, 0x5B, 0xC8 }), tag_stream(key, 3, 16));
        ASSERT_EQ(
            (vector<unsigned char>{ 0x1E, 0xD8, 0xEA, 0xEC, 0x55, 0xEC, 0x46 }),
            tag_stream(key, 4, 13));
    }

    TEST(MatchTagTests, BitLayout)
    {
        // Field element j is bits j * b up to (j + 1) * b of the Blake2xb output, least
        // significant bit of the first byte first. This is checked here bit by bit, and against
        // bits_to_field_elts, which packs items into field elements the same way but is written
        // differently, for widths that are and are not multiples of eight.
        LabelKey key = sequential_key();
        for (uint32_t b : { 1U, 7U, 8U, 13U, 16U, 21U, 24U, 31U, 59U, 60U }) {
            for (size_t felt_count : { size_t(1), size_t(3), size_t(8), size_t(65) }) {
                vector<felt_t> felts = compute_match_tag(key, felt_count, b);
                vector<unsigned char> bytes = tag_stream(key, felt_count, b);
                ASSERT_EQ(felt_count, felts.size());

                for (size_t j = 0; j < felt_count; j++) {
                    felt_t expected = 0;
                    for (uint32_t k = 0; k < b; k++) {
                        size_t i = (j * b) + k;
                        if ((bytes[i / 8] >> (i % 8)) & 1) {
                            expected |= felt_t(1) << k;
                        }
                    }
                    ASSERT_EQ(expected, felts[j]) << "b = " << b << ", j = " << j;
                    ASSERT_LT(felts[j], felt_t(1) << b);
                }

                // A modulus of b + 1 bits makes bits_to_field_elts use b bits per field element
                Modulus mod((uint64_t(1) << b) + 1);
                BitstringView<const unsigned char> bits(
                    bytes.data(), static_cast<uint32_t>(felt_count * b));
                ASSERT_EQ(bits_to_field_elts(bits, mod), felts) << "b = " << b;
            }
        }

        // 64 bits per field element is the widest allowed
        vector<felt_t> wide = compute_match_tag(key, 2, 64);
        vector<unsigned char> bytes = tag_stream(key, 2, 64);
        for (size_t j = 0; j < 2; j++) {
            felt_t expected = 0;
            for (size_t k = 0; k < 8; k++) {
                expected |= felt_t(bytes[(j * 8) + k]) << (8 * k);
            }
            ASSERT_EQ(expected, wide[j]);
        }
    }

    TEST(MatchTagTests, DependsOnKeyAndSize)
    {
        LabelKey key = sequential_key();
        LabelKey other_key = key;
        other_key[15] ^= 1;
        ASSERT_NE(compute_match_tag(key, 4, 16), compute_match_tag(other_key, 4, 16));

        // Deterministic
        ASSERT_EQ(compute_match_tag(key, 4, 16), compute_match_tag(key, 4, 16));

        // Blake2xb commits to its output length, so a longer tag does not extend a shorter one
        vector<felt_t> short_tag = compute_match_tag(key, 3, 16);
        vector<felt_t> long_tag = compute_match_tag(key, 4, 16);
        ASSERT_FALSE(equal(short_tag.begin(), short_tag.end(), long_tag.begin()));
    }

    TEST(MatchTagTests, DiffersFromTheLabelKeystream)
    {
        // Labels are encrypted with Blake2xb under the same key, on the nonce as input. With no
        // nonce, encrypting zeros reveals the keystream, which must not be the tag's bytes.
        LabelKey key = sequential_key();
        vector<unsigned char> stream = tag_stream(key, 3, 16);
        EncryptedLabel keystream = encrypt_label(Label(stream.size(), 0), key, stream.size(), 0);
        ASSERT_EQ(stream.size(), keystream.size());
        ASSERT_FALSE(equal(stream.begin(), stream.end(), keystream.begin()));

        static_assert(match_tag_domain.size() == 17, "the domain is the 17 bytes of the spec");
        ASSERT_EQ(
            string("apsi.match_tag.v1"), string(match_tag_domain.begin(), match_tag_domain.end()));
    }

    TEST(MatchTagTests, RejectsBadArguments)
    {
        LabelKey key = sequential_key();
        ASSERT_THROW(static_cast<void>(compute_match_tag(key, 0, 16)), invalid_argument);
        ASSERT_THROW(static_cast<void>(compute_match_tag(key, 3, 0)), invalid_argument);
        ASSERT_THROW(static_cast<void>(compute_match_tag(key, 3, 65)), invalid_argument);

        // Blake2xb gives at most 2^32 - 1 bytes, and this would take 2^32
        ASSERT_THROW(
            static_cast<void>(compute_match_tag(key, size_t(1) << 32, 8)), invalid_argument);
    }
} // namespace APSITests
