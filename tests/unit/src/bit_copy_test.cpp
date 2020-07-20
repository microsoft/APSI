// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstdint>
#include <random>
#include <vector>
#include "apsi/db_encoding.h"
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;

namespace
{
    unsigned char get_bit(vector<unsigned char> &vec, size_t position)
    {
        if (position >= (vec.size() * 8))
            throw out_of_range("position");

        size_t byte_idx = position >> 3;
        size_t bit_idx = position & size_t(0x7);
        unsigned char mask = static_cast<unsigned char>(0x1 << bit_idx);
        if (0 == (vec[byte_idx] & mask))
            return 0;

        return 1;
    }
} // namespace

namespace APSITests
{
    TEST(DbEncodingTests, bit_copy_test)
    {
        int trials = 1000;
        size_t size = 10;

        std::vector<unsigned char> src(size), dest(size);
        for (int t = 6; t < trials; ++t)
        {
            random_device rd;

            size_t srcOffset = rd() % (size * 4);
            size_t destOffset = rd() % (size * 4);
            size_t bitLength = rd() % (size * 4 - 1) + 1;

            int srcVal = (t & 1) * ~0;
            int destVal = ~srcVal;

            memset(src.data(), srcVal, src.size());
            memset(dest.data(), destVal, dest.size());

            apsi::details::copy_with_bit_offset(src, srcOffset, destOffset, bitLength, dest);

            size_t src_idx = srcOffset;
            size_t dst_idx = 0;

            for (size_t i = 0; i < destOffset; ++i)
            {
                ASSERT_EQ((unsigned char)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }

            for (size_t i = 0; i < bitLength; ++i)
            {
                ASSERT_EQ(get_bit(src, src_idx), get_bit(dest, dst_idx));
                src_idx++;
                dst_idx++;
            }

            size_t rem = size * 8 - destOffset - bitLength;
            for (size_t i = 0; i < rem; ++i)
            {
                ASSERT_EQ((unsigned char)(destVal & 1), get_bit(dest, dst_idx));
                dst_idx++;
            }
        }
    }

    // Tests that encoding bitstring -> field elements -> bitstring is a lossless round trip
    TEST(DbEncodingTests, encode_decode_correctness)
    {
        // Make a SEAL modulus. This defines our field
        seal::EncryptionParameters parms(seal::scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(17);
        auto context = seal::SEALContext::Create(parms);
        seal::Modulus plain_modulus = context->first_context_data()->parms().plain_modulus();

        // Make a random bitstring
        random_device rd;
        // Fill random underlying bytes
        vector<uint8_t> bytes(9767);
        std::generate(begin(bytes), end(bytes), rd);
        // Pick a random bitlen within range, i.e., within 7 bits of the total len
        std::uniform_int_distribution<int> bitlen_dist(0, 7);
        size_t bit_len = bytes.size()*8 - bitlen_dist(rd);
        // Make the Bitstring object
        Bitstring bitstring(bytes, bit_len);

        // Now do a round trip
        vector<uint64_t> felts = bits_to_field_elts(bitstring, mod);
        Bitstring rederived_bitstring = field_elts_to_bits(felts, bit_len, mod);

        // Make sure that the round trip is the identity
        ASSERT_EQ(bitstring, rederived_bitstring);
    }
} // namespace APSITests
