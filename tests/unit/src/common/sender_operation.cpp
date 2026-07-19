// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <sstream>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"

// SEAL
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    TEST(SenderOperationTest, SaveLoadHeader)
    {
        SenderOperationHeader header;
        stringstream ss;

        header.type = SenderOperationType::sop_unknown;
        header.version = 999;
        size_t out_size = header.save(ss);

        SenderOperationHeader header2;
        size_t in_size = header2.load(ss);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(header.type, header2.type);
        ASSERT_EQ(header.version, header2.version);

        header.type = SenderOperationType::sop_query;
        header.version = 123;
        out_size = header.save(ss);

        in_size = header2.load(ss);
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(header.type, header2.type);
        ASSERT_EQ(header.version, header2.version);
    }

    TEST(SenderOperationTest, SaveLoadSenderOperationParms)
    {
        SenderOperationParms sop;
        ASSERT_EQ(SenderOperationType::sop_parms, sop.type());

        stringstream ss;
        size_t out_size = sop.save(ss);
        SenderOperationParms sop2;
        size_t in_size = sop2.load(ss, nullptr);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_parms, sop2.type());
    }

    TEST(SenderOperationTest, SaveLoadSenderOperationOPRF)
    {
        SenderOperationOPRF sop;
        ASSERT_EQ(SenderOperationType::sop_oprf, sop.type());
        ASSERT_TRUE(sop.data.empty());

        stringstream ss;

        // Save with no data
        size_t out_size = sop.save(ss);
        SenderOperationOPRF sop2;
        size_t in_size = sop2.load(ss, nullptr);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sop2.type());
        ASSERT_TRUE(sop2.data.empty());

        sop.data.push_back(0xAB);
        out_size = sop.save(ss);
        in_size = sop2.load(ss, nullptr);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sop2.type());
        ASSERT_EQ(1, sop2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sop2.data[0]));

        sop.data.push_back(0xCD);
        out_size = sop.save(ss);
        in_size = sop2.load(ss, nullptr);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_oprf, sop2.type());
        ASSERT_EQ(2, sop2.data.size());
        ASSERT_EQ(static_cast<char>(0xAB), static_cast<char>(sop2.data[0]));
        ASSERT_EQ(static_cast<char>(0xCD), static_cast<char>(sop2.data[1]));
    }

    TEST(SenderOperationTest, SaveLoadSenderOperationQuery)
    {
        // Constructor
        SenderOperationQuery sop;
        ASSERT_EQ(SenderOperationType::sop_query, sop.type());
        ASSERT_EQ(Serialization::compr_mode_default, sop.compr_mode);
        ASSERT_FALSE(sop.relin_keys.is_local());
        ASSERT_FALSE(sop.relin_keys.is_serializable());
        ASSERT_TRUE(sop.data.empty());

        stringstream ss;

        // Set up the SEAL objects
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
        parms.set_plain_modulus(17);
        auto context = make_shared<SEALContext>(parms);
        KeyGenerator keygen(*context);

        // A local (invalid/empty) relin_keys object
        // For the query we allow an empty data field
        sop.relin_keys.set(RelinKeys());
        ASSERT_FALSE(sop.relin_keys.is_serializable());
        ASSERT_TRUE(sop.relin_keys.is_local());

        size_t out_size = sop.save(ss);
        SenderOperationQuery sop2;

        // Loading a query requires a valid SEALContext
        size_t in_size = 0;
        ASSERT_THROW(in_size = sop2.load(ss, nullptr), invalid_argument);

        // Loading a query requires the RelinKeys to be valid
        ASSERT_THROW(in_size = sop2.load(ss, context), runtime_error);

        // A local valid relin_keys object; this time also load works
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        sop.relin_keys.set(std::move(rlk));
        ASSERT_FALSE(sop.relin_keys.is_serializable());
        ASSERT_TRUE(sop.relin_keys.is_local());
        out_size = sop.save(ss);
        in_size = sop2.load(ss, context);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sop2.type());
        ASSERT_FALSE(sop2.relin_keys.is_serializable());
        ASSERT_TRUE(sop2.relin_keys.is_local());
        ASSERT_TRUE(sop2.data.empty());

        // A serializable relin_keys object
        sop.relin_keys.set(keygen.create_relin_keys());
        ASSERT_TRUE(sop.relin_keys.is_serializable());
        ASSERT_FALSE(sop.relin_keys.is_local());
        out_size = sop.save(ss);
        in_size = sop2.load(ss, context);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sop2.type());
        ASSERT_FALSE(sop2.relin_keys.is_serializable());
        ASSERT_TRUE(sop2.relin_keys.is_local());
        ASSERT_TRUE(sop2.data.empty());

        // Now add some (empty and non-empty) data as well
        sop.data[0] = {};
        sop.data[1].emplace_back(Ciphertext(*context));
        sop.data[5].emplace_back(Ciphertext(*context));
        sop.data[5].emplace_back(Ciphertext(*context));
        ASSERT_EQ(3, sop.data.size());
        out_size = sop.save(ss);
        in_size = sop2.load(ss, context);

        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(SenderOperationType::sop_query, sop2.type());
        ASSERT_EQ(3, sop2.data.size());
        ASSERT_TRUE(sop2.data.at(0).empty());
        ASSERT_EQ(1, sop2.data.at(1).size());
        ASSERT_EQ(2, sop2.data.at(5).size());
    }
} // namespace APSITests
