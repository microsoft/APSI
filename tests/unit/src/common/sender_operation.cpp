// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sop_generated.h"

// SEAL
#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/serialization.h"
#include "seal/valcheck.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        vector<compr_mode_type> supported_compr_modes()
        {
            vector<compr_mode_type> compr_modes;
            for (unsigned value = 0; value <= 0xFF; value++) {
                if (Serialization::IsSupportedComprMode(static_cast<uint8_t>(value))) {
                    compr_modes.push_back(static_cast<compr_mode_type>(value));
                }
            }
            return compr_modes;
        }

        shared_ptr<SEALContext> make_context()
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(4096);
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
            parms.set_plain_modulus(65537);
            return make_shared<SEALContext>(parms);
        }

        const fbs::QueryRequest *get_query_request(const string &saved)
        {
            return fbs::GetSizePrefixedSenderOperation(saved.data())->request_as_QueryRequest();
        }
    } // namespace

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

    TEST(SenderOperationTest, SaveLoadSenderOperationQueryInEveryComprMode)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);
        Encryptor encryptor(*context, keygen.secret_key());
        Decryptor decryptor(*context, keygen.secret_key());
        BatchEncoder encoder(*context);

        vector<uint64_t> values(encoder.slot_count());
        iota(values.begin(), values.end(), static_cast<uint64_t>(1));
        Plaintext pt;
        encoder.encode(values, pt);

        // At least none and bitpack, which Microsoft SEAL always supports
        vector<compr_mode_type> compr_modes = supported_compr_modes();
        ASSERT_LE(size_t(2), compr_modes.size());
        ASSERT_EQ(compr_mode_type::none, compr_modes.front());

        size_t uncompressed_size = 0;
        for (compr_mode_type compr_mode : compr_modes) {
            SCOPED_TRACE(compr_mode_str(compr_mode));

            // Seeded keys and ciphertexts, as a receiver sends them
            SenderOperationQuery sop;
            sop.compr_mode = compr_mode;
            sop.relin_keys.set(keygen.create_relin_keys());
            sop.data[1].emplace_back(encryptor.encrypt_symmetric(pt));
            sop.data[2].emplace_back(encryptor.encrypt_symmetric(pt));

            stringstream ss;
            size_t out_size = sop.save(ss);
            string saved = ss.str();

            // Every Microsoft SEAL object in the query is saved in the query's mode. Bit-packed
            // ones carry the format version that earlier releases of Microsoft SEAL reject.
            const auto *req = get_query_request(saved);
            ASSERT_EQ(static_cast<uint8_t>(compr_mode), req->compression_type());
            vector<const flatbuffers::Vector<uint8_t> *> seal_objects{ req->relin_keys() };
            for (const auto *query_part : *req->query()) {
                for (const auto *ct : *query_part->cts()) {
                    seal_objects.push_back(ct->data());
                }
            }
            ASSERT_EQ(size_t(3), seal_objects.size());
            for (const auto *seal_object : seal_objects) {
                Serialization::SEALHeader header;
                Serialization::LoadHeader(
                    reinterpret_cast<const seal_byte *>(seal_object->data()),
                    seal_object->size(),
                    header,
                    false);
                ASSERT_EQ(compr_mode, header.compr_mode);
                ASSERT_EQ(Serialization::format_version_major, header.version_major);
                ASSERT_EQ(
                    compr_mode == compr_mode_type::bitpack
                        ? Serialization::format_version_minor_bitpack
                        : Serialization::format_version_minor,
                    header.version_minor);
            }

            if (compr_mode == compr_mode_type::none) {
                uncompressed_size = out_size;
            } else {
                ASSERT_GT(uncompressed_size, out_size);
            }

            SenderOperationQuery sop2;
            size_t in_size = sop2.load(ss, context);
            ASSERT_EQ(out_size, in_size);
            ASSERT_EQ(compr_mode, sop2.compr_mode);
            ASSERT_TRUE(is_valid_for(sop2.relin_keys.extract(context), *context));
            ASSERT_EQ(size_t(2), sop2.data.size());
            for (uint32_t exponent : { 1U, 2U }) {
                ASSERT_EQ(size_t(1), sop2.data.at(exponent).size());
                Ciphertext ct = sop2.data.at(exponent)[0].extract(context);
                Plaintext decrypted;
                decryptor.decrypt(ct, decrypted);
                vector<uint64_t> decoded;
                encoder.decode(decrypted, decoded);
                ASSERT_EQ(values, decoded);
            }
        }
    }

    TEST(SenderOperationTest, ComprModeStr)
    {
        ASSERT_STREQ("none", compr_mode_str(compr_mode_type::none));
#ifdef SEAL_USE_ZLIB
        ASSERT_STREQ("zlib", compr_mode_str(compr_mode_type::zlib));
#endif
#ifdef SEAL_USE_ZSTD
        ASSERT_STREQ("zstd", compr_mode_str(compr_mode_type::zstd));
#endif
        ASSERT_STREQ("bitpack", compr_mode_str(compr_mode_type::bitpack));
        ASSERT_STREQ("unsupported", compr_mode_str(static_cast<compr_mode_type>(0x7F)));
    }
} // namespace APSITests
