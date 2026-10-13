// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"
#include "apsi/network/sop_generated.h"
#include "apsi/psi_params.h"

// SEAL
#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/serialization.h"
#include "seal/valcheck.h"

// GSL
#include "gsl/span"

// Google Test
#include "gtest/gtest.h"

#ifndef _WIN32
// POSIX
#include <sys/mman.h>
#endif

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

        shared_ptr<SEALContext> make_context(size_t coeff_modulus_size = 3)
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(4096);
            vector<Modulus> coeff_modulus = CoeffModulus::BFVDefault(4096);
            coeff_modulus.resize(coeff_modulus_size);
            parms.set_coeff_modulus(coeff_modulus);
            parms.set_plain_modulus(65537);
            return make_shared<SEALContext>(parms);
        }

        gsl::span<const unsigned char> as_span(const string &bytes)
        {
            return { reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size() };
        }

        const fbs::QueryRequest *get_query_request(const string &saved)
        {
            return fbs::GetSizePrefixedSenderOperation(saved.data())->request_as_QueryRequest();
        }

        string save_to_string(const SenderOperation &sop)
        {
            stringstream ss;
            sop.save(ss);
            return ss.str();
        }

        /**
        Builds a serialized query by hand, with a parameter fingerprint of any size.
        */
        string make_query_with_fingerprint(const vector<uint8_t> &fingerprint)
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            auto query =
                fbs_builder.CreateVector(vector<flatbuffers::Offset<fbs::QueryRequestPart>>{});
            auto params_fingerprint = fbs_builder.CreateVector(fingerprint);
            auto req = fbs::CreateQueryRequest(
                fbs_builder,
                static_cast<uint8_t>(compr_mode_type::none),
                0,
                query,
                params_fingerprint);
            auto sop =
                fbs::CreateSenderOperation(fbs_builder, fbs::Request_QueryRequest, req.Union());
            fbs_builder.FinishSizePrefixed(sop);
            return { reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                     fbs_builder.GetSize() };
        }

#ifndef _WIN32
        /**
        Anonymous memory mapped for reading and writing, which reads as zeros until written. The
        operating system backs only the pages that are touched, so it can be far larger than the
        memory it uses. data() is null if the memory could not be mapped.
        */
        class MappedMemory {
        public:
            explicit MappedMemory(size_t size) : size_(size)
            {
                void *data =
                    mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
                if (data != MAP_FAILED) {
                    data_ = static_cast<unsigned char *>(data);
                }
            }

            ~MappedMemory()
            {
                if (data_) {
                    munmap(data_, size_);
                }
            }

            MappedMemory(const MappedMemory &) = delete;

            MappedMemory &operator=(const MappedMemory &) = delete;

            [[nodiscard]] unsigned char *data() const noexcept
            {
                return data_;
            }

        private:
            size_t size_;

            unsigned char *data_ = nullptr;
        };
#endif
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

        // The ciphertexts are held as they were received, and loaded when they are extracted
        for (uint32_t exponent : { 1U, 5U }) {
            for (auto &ct : sop2.data.at(exponent)) {
                ASSERT_TRUE(ct.is_serialized());
                ASSERT_NO_THROW((void)ct.extract(context));
            }
        }
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
                ASSERT_TRUE(sop2.data.at(exponent)[0].is_serialized());
                Ciphertext ct = sop2.data.at(exponent)[0].extract(context);
                Plaintext decrypted;
                decryptor.decrypt(ct, decrypted);
                vector<uint64_t> decoded;
                encoder.decode(decrypted, decoded);
                ASSERT_EQ(values, decoded);
            }
        }
    }

    TEST(SenderOperationTest, SaveLoadSenderOperationQueryParamsFingerprint)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);

        SenderOperationQuery sop;
        sop.relin_keys.set(keygen.create_relin_keys());
        ASSERT_FALSE(sop.params_fingerprint);

        // Without a fingerprint the field is absent, as in a query from a receiver before APSI 2.0
        string saved = save_to_string(sop);
        ASSERT_EQ(nullptr, get_query_request(saved)->params_fingerprint());

        // Loading a query without a fingerprint clears the one held before
        SenderOperationQuery sop2;
        sop2.params_fingerprint = PSIParams::Fingerprint{};
        stringstream ss(saved);
        sop2.load(ss, context);
        ASSERT_FALSE(sop2.params_fingerprint);

        PSIParams::Fingerprint fingerprint{};
        iota(fingerprint.begin(), fingerprint.end(), static_cast<unsigned char>(1));
        sop.params_fingerprint = fingerprint;
        saved = save_to_string(sop);
        ASSERT_NE(nullptr, get_query_request(saved)->params_fingerprint());
        stringstream ss2(saved);
        sop2.load(ss2, context);
        ASSERT_EQ(fingerprint, sop2.params_fingerprint);
    }

    TEST(SenderOperationTest, SaveSenderOperationQueryWithoutParamsFingerprintIsAsInAPSI1x)
    {
        // A query without a fingerprint, saved by APSI 1.1.0. It holds no Microsoft SEAL objects,
        // so these bytes do not depend on the version of Microsoft SEAL either.
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
        const unsigned char saved_by_apsi_1_1[] = {
            0x54, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x09,
            0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x0a, 0x00, 0x10, 0x00, 0x07, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x28, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x04,
            0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        // Zstandard, which receivers used by default before APSI 2.0
        SenderOperationQuery sop;
        sop.compr_mode = static_cast<compr_mode_type>(2);
        sop.data[1] = {};
        string saved = save_to_string(sop);
        ASSERT_EQ(
            string(reinterpret_cast<const char *>(saved_by_apsi_1_1), sizeof(saved_by_apsi_1_1)),
            saved);
    }

    TEST(SenderOperationTest, LoadRejectsAParamsFingerprintOfTheWrongSize)
    {
        // A single prime, so that the query needs no relinearization keys
        auto context = make_context(1);
        ASSERT_FALSE(context->using_keyswitching());

        for (size_t size : { 0U, 1U, 31U, 33U, 64U }) {
            SCOPED_TRACE(size);
            string saved = make_query_with_fingerprint(vector<uint8_t>(size, 0xAB));

            stringstream ss(saved);
            SenderOperationQuery sop;
            ASSERT_THROW(sop.load(ss, context), runtime_error);
            ASSERT_THROW(
                static_cast<void>(SenderOperationQuery::ExtractParamsFingerprint(as_span(saved))),
                runtime_error);
        }

        string saved =
            make_query_with_fingerprint(vector<uint8_t>(PSIParams::fingerprint_byte_count, 0xAB));
        PSIParams::Fingerprint expected{};
        expected.fill(0xAB);

        stringstream ss(saved);
        SenderOperationQuery sop;
        sop.load(ss, context);
        ASSERT_EQ(expected, sop.params_fingerprint);
        ASSERT_EQ(expected, SenderOperationQuery::ExtractParamsFingerprint(as_span(saved)));
    }

    TEST(SenderOperationTest, ExtractParamsFingerprint)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);
        Encryptor encryptor(*context, keygen.secret_key());

        PSIParams::Fingerprint fingerprint{};
        iota(fingerprint.begin(), fingerprint.end(), static_cast<unsigned char>(100));

        SenderOperationQuery sop;
        sop.relin_keys.set(keygen.create_relin_keys());
        sop.data[1].emplace_back(encryptor.encrypt_zero_symmetric());
        sop.params_fingerprint = fingerprint;
        string saved = save_to_string(sop);

        ASSERT_EQ(fingerprint, SenderOperationQuery::ExtractParamsFingerprint(as_span(saved)));

        // Bytes after the query are ignored
        ASSERT_EQ(
            fingerprint,
            SenderOperationQuery::ExtractParamsFingerprint(as_span(saved + string(100, '\x7f'))));

        // The buffer need not be aligned
        vector<unsigned char> shifted(saved.size() + 1);
        copy(saved.begin(), saved.end(), shifted.begin() + 1);
        ASSERT_EQ(
            fingerprint,
            SenderOperationQuery::ExtractParamsFingerprint({ shifted.data() + 1, saved.size() }));

        // Nothing but the fingerprint is read: a query with a corrupted ciphertext still yields its
        // fingerprint. Loading the query does not load the ciphertext either, which fails only
        // when it is extracted.
        string corrupted = saved;
        const auto *ct_data = get_query_request(corrupted)->query()->Get(0)->cts()->Get(0)->data();
        auto ct_offset = static_cast<size_t>(
            ct_data->data() - reinterpret_cast<const uint8_t *>(corrupted.data()));
        corrupted[ct_offset] = static_cast<char>(~corrupted[ct_offset]);
        ASSERT_EQ(fingerprint, SenderOperationQuery::ExtractParamsFingerprint(as_span(corrupted)));
        stringstream corrupted_ss(corrupted);
        SenderOperationQuery sop2;
        sop2.load(corrupted_ss, context);
        ASSERT_TRUE(sop2.data.at(1)[0].is_serialized());
        ASSERT_THROW((void)sop2.data.at(1)[0].extract(context), logic_error);

        // A query without a fingerprint
        sop.params_fingerprint.reset();
        ASSERT_EQ(
            nullopt, SenderOperationQuery::ExtractParamsFingerprint(as_span(save_to_string(sop))));

        // Too short to hold the size, and shorter than the size says
        ASSERT_THROW(
            static_cast<void>(
                SenderOperationQuery::ExtractParamsFingerprint(as_span(saved).first(3))),
            runtime_error);
        ASSERT_THROW(
            static_cast<void>(SenderOperationQuery::ExtractParamsFingerprint(
                as_span(saved).first(saved.size() - 1))),
            runtime_error);

        // Not a valid buffer
        string garbage = saved;
        for (size_t i = sizeof(uint32_t); i < garbage.size(); i++) {
            garbage[i] = static_cast<char>((i * 7) + 3);
        }
        ASSERT_THROW(
            static_cast<void>(SenderOperationQuery::ExtractParamsFingerprint(as_span(garbage))),
            runtime_error);

        // Not a query
        SenderOperationOPRF oprf;
        oprf.data = { 1, 2, 3 };
        ASSERT_THROW(
            static_cast<void>(
                SenderOperationQuery::ExtractParamsFingerprint(as_span(save_to_string(oprf)))),
            runtime_error);
    }

    TEST(SenderOperationTest, ExtractParamsFingerprintRefusesTooLargeABuffer)
    {
        // The FlatBuffers verifier asserts that a buffer is smaller than
        // FLATBUFFERS_MAX_BUFFER_SIZE, which is INT32_MAX, so a size prefix that makes the buffer,
        // with the prefix, any larger is refused before the buffer is verified. Only a buffer
        // that is as large as its prefix says gets that far, so the query is put at the start of
        // 2 GiB of mapped memory, of which only the first page is ever touched.
#ifdef _WIN32
        GTEST_SKIP() << "maps memory with mmap, which Windows does not have";
#else
        constexpr auto max_size = static_cast<size_t>(FLATBUFFERS_MAX_BUFFER_SIZE);
        MappedMemory memory(max_size);
        if (!memory.data()) {
            GTEST_SKIP() << "cannot map 2 GiB of memory";
        }

        PSIParams::Fingerprint fingerprint{};
        iota(fingerprint.begin(), fingerprint.end(), static_cast<unsigned char>(100));
        string query =
            make_query_with_fingerprint(vector<uint8_t>(fingerprint.begin(), fingerprint.end()));
        copy(query.begin(), query.end(), memory.data());

        auto extract = [&](uint32_t prefixed_size) {
            prefixed_size = flatbuffers::EndianScalar(prefixed_size);
            memcpy(memory.data(), &prefixed_size, sizeof(prefixed_size));
            return SenderOperationQuery::ExtractParamsFingerprint({ memory.data(), max_size });
        };

        // With the largest size prefix allowed, the buffer is the query and zeros after it, which
        // are not read
        ASSERT_EQ(fingerprint, extract(static_cast<uint32_t>(max_size - sizeof(uint32_t) - 1)));

        // One more is refused
        try {
            static_cast<void>(extract(static_cast<uint32_t>(max_size - sizeof(uint32_t))));
            FAIL() << "a buffer of FLATBUFFERS_MAX_BUFFER_SIZE bytes was accepted";
        } catch (const runtime_error &ex) {
            ASSERT_STREQ("failed to load SenderOperation: buffer is too large", ex.what());
        }
#endif
    }

    TEST(SenderOperationTest, LoadHoldsQueryCiphertextsAsTheyWereReceived)
    {
        // A single prime, so that the query needs no relinearization keys and holds nothing but
        // the ciphertexts put in it here
        auto context = make_context(1);
        ASSERT_FALSE(context->using_keyswitching());
        KeyGenerator keygen(*context);
        Encryptor encryptor(*context, keygen.secret_key());

        // A ciphertext as a receiver sends it, and bytes that are not a ciphertext at all
        SEALObject<Ciphertext> garbage;
        garbage.set_serialized(vector<unsigned char>(100, 0x5A));
        SenderOperationQuery sop;
        sop.data[1].emplace_back(encryptor.encrypt_zero_symmetric());
        sop.data[1].push_back(garbage);
        string saved = save_to_string(sop);

        // Loading copies the bytes of each ciphertext without looking at them
        stringstream ss(saved);
        SenderOperationQuery sop2;
        ASSERT_EQ(saved.size(), sop2.load(ss, context));
        ASSERT_EQ(size_t(2), sop2.data.at(1).size());
        ASSERT_TRUE(sop2.data.at(1)[0].is_serialized());
        ASSERT_TRUE(sop2.data.at(1)[1].is_serialized());

        // Saved again, the query is what was received, byte for byte
        ASSERT_EQ(saved, save_to_string(sop2));

        // A ciphertext is loaded, and validated, when it is extracted
        ASSERT_TRUE(is_valid_for(sop2.data.at(1)[0].extract(context), *context));
        ASSERT_THROW((void)sop2.data.at(1)[1].extract(context), logic_error);
    }

    namespace {
        /**
        Returns the bytes Microsoft SEAL saves the object as.
        */
        template <typename T>
        vector<unsigned char> seal_save(const T &obj, compr_mode_type compr_mode)
        {
            vector<unsigned char> bytes(static_cast<size_t>(obj.save_size(compr_mode)));
            auto size =
                obj.save(reinterpret_cast<seal_byte *>(bytes.data()), bytes.size(), compr_mode);
            bytes.resize(static_cast<size_t>(size));
            return bytes;
        }

        /**
        Returns what save_members writes, saved as Microsoft SEAL saves an object: after a
        SEALHeader, in the given compression mode. member_byte_count must be the number of bytes
        save_members writes.
        */
        vector<unsigned char> seal_save_members(
            const function<void(ostream &)> &save_members,
            size_t member_byte_count,
            compr_mode_type compr_mode)
        {
            size_t header_size = sizeof(Serialization::SEALHeader);
            vector<unsigned char> bytes(
                header_size + Serialization::ComprSizeEstimate(member_byte_count, compr_mode));
            auto size = Serialization::Save(
                save_members,
                static_cast<streamoff>(header_size) + static_cast<streamoff>(member_byte_count),
                reinterpret_cast<seal_byte *>(bytes.data()),
                bytes.size(),
                compr_mode,
                false);
            bytes.resize(static_cast<size_t>(size));
            return bytes;
        }

        /**
        Returns the message of the std::runtime_error that loading a query with the given bytes
        for its relinearization keys throws, or an empty string if loading succeeds, in which
        case the keys loaded are returned in loaded.
        */
        string load_query_with_relin_keys(
            const shared_ptr<SEALContext> &context,
            const vector<unsigned char> &relin_keys,
            RelinKeys *loaded = nullptr)
        {
            SenderOperationQuery sop;
            sop.relin_keys.set_serialized(relin_keys);
            stringstream ss;
            sop.save(ss);

            SenderOperationQuery sop2;
            try {
                sop2.load(ss, context);
            } catch (const runtime_error &ex) {
                return ex.what();
            }
            if (loaded) {
                *loaded = sop2.relin_keys.extract(context);
            }
            return {};
        }

        /**
        Returns relinearization keys that declare as many key sets as Microsoft SEAL accepts,
        poly_modulus_degree of them, each with as many keys as honest keys have, and every key a
        valid public key whose data is zero. They are saved in the given compression mode, with
        every key compressed on its own besides, as Microsoft SEAL allows, so that they never have
        to be held in memory to be written. The number of bytes loading them would allocate for
        the data of their keys is returned in loaded_byte_count.
        */
        vector<unsigned char> save_inflated_relin_keys(
            const SEALContext &context, compr_mode_type compr_mode, size_t &loaded_byte_count)
        {
            PublicKey zero_key;
            zero_key.data().resize(context, context.key_parms_id(), 2);
            zero_key.data().is_ntt_form() = true;
            compr_mode_type key_compr_mode =
                Serialization::compr_mode_default == compr_mode_type::none
                    ? compr_mode_type::bitpack
                    : Serialization::compr_mode_default;
            vector<unsigned char> key_bytes = seal_save(zero_key, key_compr_mode);

            parms_id_type parms_id = context.key_parms_id();
            uint64_t key_set_count = context.key_context_data()->parms().poly_modulus_degree();
            uint64_t key_count = context.first_context_data()->parms().coeff_modulus().size();
            size_t member_byte_count =
                sizeof(parms_id) + sizeof(key_set_count) +
                (key_set_count * (sizeof(key_count) + (key_count * key_bytes.size())));
            auto save_members = [&](ostream &stream) {
                stream.write(reinterpret_cast<const char *>(&parms_id), sizeof(parms_id));
                stream.write(reinterpret_cast<const char *>(&key_set_count), sizeof(key_set_count));
                for (uint64_t i = 0; i < key_set_count; i++) {
                    stream.write(reinterpret_cast<const char *>(&key_count), sizeof(key_count));
                    for (uint64_t j = 0; j < key_count; j++) {
                        stream.write(
                            reinterpret_cast<const char *>(key_bytes.data()),
                            static_cast<streamsize>(key_bytes.size()));
                    }
                }
            };

            loaded_byte_count =
                key_set_count * key_count * zero_key.data().dyn_array().size() * sizeof(uint64_t);
            return seal_save_members(save_members, member_byte_count, compr_mode);
        }
    } // namespace

    TEST(SenderOperationTest, LoadRefusesQueryCiphertextsThatShareBytes)
    {
        // A receiver saves every ciphertext of a query to bytes of its own. FlatBuffers lets many
        // offsets point at one object, and its verifier allows it, so a short query could
        // otherwise have all its entries point at one ciphertext, which loading would copy once
        // for each.
        //
        // A single prime, so that the query needs no relinearization keys
        auto context = make_context(1);
        ASSERT_FALSE(context->using_keyswitching());
        KeyGenerator keygen(*context);
        Encryptor encryptor(*context, keygen.secret_key());
        vector<unsigned char> ct =
            seal_save(encryptor.encrypt_zero_symmetric(), compr_mode_type::none);

        // A query of two powers with four ciphertexts each, every one the same, written to bytes
        // of its own or once for all
        auto make_query = [&](bool write_once) {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);
            auto write_ct = [&] {
                auto data = fbs_builder.CreateVector(ct.data(), ct.size());
                return fbs::CreateCiphertext(fbs_builder, data);
            };

            flatbuffers::Offset<fbs::Ciphertext> written_once;
            if (write_once) {
                written_once = write_ct();
            }
            vector<flatbuffers::Offset<fbs::QueryRequestPart>> parts;
            for (uint32_t exponent : { 1U, 2U }) {
                vector<flatbuffers::Offset<fbs::Ciphertext>> cts;
                for (size_t i = 0; i < 4; i++) {
                    cts.push_back(write_once ? written_once : write_ct());
                }
                auto cts_offset = fbs_builder.CreateVector(cts);
                parts.push_back(fbs::CreateQueryRequestPart(fbs_builder, exponent, cts_offset));
            }

            auto query = fbs_builder.CreateVector(parts);
            auto req = fbs::CreateQueryRequest(
                fbs_builder, static_cast<uint8_t>(compr_mode_type::none), 0, query);
            auto sop =
                fbs::CreateSenderOperation(fbs_builder, fbs::Request_QueryRequest, req.Union());
            fbs_builder.FinishSizePrefixed(sop);
            return string(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                fbs_builder.GetSize());
        };

        // Written to bytes of its own, every ciphertext is held as those bytes
        string honest = make_query(false);
        stringstream honest_ss(honest);
        SenderOperationQuery sop;
        ASSERT_EQ(honest.size(), sop.load(honest_ss, context));
        for (uint32_t exponent : { 1U, 2U }) {
            ASSERT_EQ(size_t(4), sop.data.at(exponent).size());
            for (const auto &held : sop.data.at(exponent)) {
                ASSERT_EQ(ct.size(), held.save_size(compr_mode_type::none));
            }
        }

        // Written once for all, the query takes fewer bytes than two of its ciphertexts, and is
        // refused
        string shared = make_query(true);
        ASSERT_LT(shared.size(), ct.size() * 2);
        stringstream shared_ss(shared);
        try {
            sop.load(shared_ss, context);
            FAIL() << "a query whose ciphertexts share bytes was loaded";
        } catch (const runtime_error &ex) {
            ASSERT_STREQ("invalid query data: ciphertexts share bytes", ex.what());
        }
    }

    TEST(SenderOperationTest, LoadAcceptsTheRelinKeysOfAReceiverInEveryComprMode)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);
        RelinKeys local;
        keygen.create_relin_keys(local);
        Serializable<RelinKeys> seeded = keygen.create_relin_keys();

        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));

            // Keys as a receiver sends them, seeded, and keys saved in full. The keys loaded are
            // those Microsoft SEAL loads from the same bytes.
            for (const auto &bytes :
                 { seal_save(seeded, compr_mode), seal_save(local, compr_mode) }) {
                RelinKeys loaded;
                ASSERT_EQ(string(), load_query_with_relin_keys(context, bytes, &loaded));

                RelinKeys expected;
                expected.load(
                    *context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size());
                ASSERT_EQ(
                    seal_save(expected, compr_mode_type::none),
                    seal_save(loaded, compr_mode_type::none));
            }
        }
    }

    TEST(SenderOperationTest, LoadRejectsRelinKeysThatAreNotOneKeySet)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);

        RelinKeys one_set;
        keygen.create_relin_keys(one_set);
        ASSERT_EQ(size_t(1), one_set.data().size());
        ASSERT_EQ(size_t(1), one_set.size());

        // Keys that Microsoft SEAL loads as valid, but which no receiver sends: a second key set,
        // a single key set that is not the one for the square of the secret key, and none
        RelinKeys two_sets = one_set;
        two_sets.data().push_back(one_set.data()[0]);
        RelinKeys other_set = one_set;
        other_set.data().insert(other_set.data().begin(), vector<PublicKey>{});
        RelinKeys no_set = one_set;
        no_set.data().clear();

        vector<pair<const RelinKeys *, string>> cases{
            { &two_sets, "they declare a key set count of 2, not 1" },
            { &other_set, "they declare a key set count of 2, not 1" },
            { &no_set, "they declare a key set count of 0, not 1" },
        };
        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));
            for (const auto &[relin_keys, error] : cases) {
                ASSERT_TRUE(is_valid_for(*relin_keys, *context));
                ASSERT_EQ(
                    "failed to load relinearization keys: " + error,
                    load_query_with_relin_keys(context, seal_save(*relin_keys, compr_mode)));
            }
        }
    }

    TEST(SenderOperationTest, LoadRejectsRelinKeysWithAKeySetOfAnotherSize)
    {
        // A key set has a key for each prime of the first data level, two for these parameters
        auto context = make_context();
        ASSERT_EQ(size_t(2), context->first_context_data()->parms().coeff_modulus().size());
        KeyGenerator keygen(*context);

        RelinKeys one_set;
        keygen.create_relin_keys(one_set);
        RelinKeys fewer = one_set;
        fewer.data()[0].pop_back();
        RelinKeys more = one_set;
        more.data()[0].push_back(one_set.data()[0][0]);

        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));
            ASSERT_EQ(
                string(
                    "failed to load relinearization keys: their key set declares a key count "
                    "of 1, not 2"),
                load_query_with_relin_keys(context, seal_save(fewer, compr_mode)));
            ASSERT_EQ(
                string(
                    "failed to load relinearization keys: their key set declares a key count "
                    "of 3, not 2"),
                load_query_with_relin_keys(context, seal_save(more, compr_mode)));
        }
    }

    TEST(SenderOperationTest, LoadRejectsInflatedRelinKeysWithoutLoadingThem)
    {
        // Microsoft SEAL accepts up to poly_modulus_degree key sets, and keys whose data is zero
        // compress to almost nothing: these declare more than a gigabyte of keys in a fiftieth of
        // that or less, whichever compressors Microsoft SEAL was built with, and in a few hundred
        // bytes with Zstandard. They are refused for the dimensions they declare, which are read
        // before any key is loaded, and therefore quickly.
        auto context = make_context();
        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));

            size_t loaded_byte_count = 0;
            vector<unsigned char> bytes =
                save_inflated_relin_keys(*context, compr_mode, loaded_byte_count);
            ASSERT_GT(loaded_byte_count, size_t(1) << 30);
            ASSERT_LT(bytes.size() * 50, loaded_byte_count);

            auto start = chrono::steady_clock::now();
            ASSERT_EQ(
                string(
                    "failed to load relinearization keys: they declare a key set count of "
                    "4096, not 1"),
                load_query_with_relin_keys(context, bytes));

            // The message says the keys were refused for the dimensions they declare. The bound is
            // loose on purpose: it only catches a pathological regression, not a slow machine.
            ASSERT_LT(chrono::steady_clock::now() - start, chrono::seconds(30));
        }
    }

    TEST(SenderOperationTest, LoadRejectsRelinKeysThatCannotBeRead)
    {
        auto context = make_context();
        KeyGenerator keygen(*context);
        RelinKeys one_set;
        keygen.create_relin_keys(one_set);
        parms_id_type parms_id = context->key_parms_id();
        uint64_t one = 1;
        uint64_t key_count = context->first_context_data()->parms().coeff_modulus().size();

        // Members that end in the middle of what is read before any key is loaded, or before the
        // keys they declare
        auto write = [](ostream &stream, const auto &value) {
            stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
        };
        vector<pair<function<void(ostream &)>, size_t>> short_members{
            { [&](ostream &stream) { write(stream, parms_id); }, sizeof(parms_id) },
            { [&](ostream &stream) {
                 write(stream, parms_id);
                 write(stream, one);
             },
              sizeof(parms_id) + sizeof(one) },
            { [&](ostream &stream) {
                 write(stream, parms_id);
                 write(stream, one);
                 write(stream, key_count);
             },
              sizeof(parms_id) + sizeof(one) + sizeof(key_count) },
        };

        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(compr_mode_str(compr_mode));

            // Bytes that are not keys at all, and keys cut short anywhere, including inside the
            // SEALHeader
            vector<vector<unsigned char>> unreadable{ vector<unsigned char>(100, 0x5A) };
            vector<unsigned char> saved = seal_save(one_set, compr_mode);
            vector<size_t> cuts{ 0, 8, 16, saved.size() / 2, saved.size() - 1 };
            for (size_t cut : cuts) {
                unreadable.emplace_back(saved.begin(), saved.begin() + static_cast<ptrdiff_t>(cut));
            }
            for (const auto &[save_members, member_byte_count] : short_members) {
                unreadable.push_back(
                    seal_save_members(save_members, member_byte_count, compr_mode));
            }

            for (const auto &bytes : unreadable) {
                SCOPED_TRACE(bytes.size());
                string error = load_query_with_relin_keys(context, bytes);
                ASSERT_EQ(size_t(0), error.find("failed to load relinearization keys: "));
                ASSERT_EQ(string::npos, error.find("declare"));
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
