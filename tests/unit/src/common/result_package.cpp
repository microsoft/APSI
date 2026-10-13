// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/network/result_package.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/psi_params.h"

// SEAL
#include "seal/context.h"
#include "seal/keygenerator.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        shared_ptr<PSIParams> get_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 8;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 8;
                table_params.table_size = 512;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        /**
        Parameters with match tags: three tag parts of 16 bits, one field element per item, and two
        bundle indices.
        */
        shared_ptr<PSIParams> get_tag_params()
        {
            static shared_ptr<PSIParams> params = nullptr;
            if (!params) {
                PSIParams::ItemParams item_params;
                item_params.felts_per_item = 1;
                item_params.tag_part_count = 3;

                PSIParams::TableParams table_params;
                table_params.hash_func_count = 3;
                table_params.max_items_per_bin = 8;
                table_params.table_size = 8192;

                PSIParams::QueryParams query_params;
                query_params.query_powers = { 1, 3, 5 };

                size_t pmd = 4096;
                PSIParams::SEALParams seal_params;
                seal_params.set_poly_modulus_degree(pmd);
                seal_params.set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
                seal_params.set_plain_modulus(65537);

                params =
                    make_shared<PSIParams>(item_params, table_params, query_params, seal_params);
            }

            return params;
        }

        vector<unsigned char> ciphertext_bytes(const Ciphertext &ct, compr_mode_type compr_mode)
        {
            SEALObject<Ciphertext> obj(ct);
            vector<unsigned char> bytes(obj.save_size(compr_mode));
            bytes.resize(obj.save(bytes, compr_mode));
            return bytes;
        }

        /**
        A serialized result package written field by field, in the order ResultPackage::save
        writes them, so that a test can write combinations save never does. psi_ct is left out
        when null. The ciphertexts are raw bytes, which need not be valid ciphertexts.
        */
        string raw_package(
            uint32_t bundle_idx,
            const vector<unsigned char> *psi_ct,
            uint32_t label_byte_count,
            uint32_t nonce_byte_count,
            const vector<vector<unsigned char>> &label_cts)
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            flatbuffers::Offset<fbs::Ciphertext> psi_ct_offset;
            if (psi_ct) {
                auto data = fbs_builder.CreateVector(psi_ct->data(), psi_ct->size());
                psi_ct_offset = fbs::CreateCiphertext(fbs_builder, data);
            }

            auto label_cts_offset = fbs_builder.CreateVector([&] {
                vector<flatbuffers::Offset<fbs::Ciphertext>> ret;
                for (const auto &label_ct : label_cts) {
                    auto data = fbs_builder.CreateVector(label_ct.data(), label_ct.size());
                    ret.push_back(fbs::CreateCiphertext(fbs_builder, data));
                }
                return ret;
            }());

            fbs::ResultPackageBuilder rp_builder(fbs_builder);
            rp_builder.add_bundle_idx(bundle_idx);
            if (psi_ct) {
                rp_builder.add_psi_result(psi_ct_offset);
            }
            rp_builder.add_label_byte_count(label_byte_count);
            rp_builder.add_nonce_byte_count(nonce_byte_count);
            rp_builder.add_label_result(label_cts_offset);
            auto rp = rp_builder.Finish();
            fbs_builder.FinishSizePrefixed(rp);

            return { reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                     fbs_builder.GetSize() };
        }

        /**
        Encrypts a vector of slot values, every slot set to value.
        */
        Ciphertext encrypt_value(const CryptoContext &context, uint64_t value)
        {
            vector<uint64_t> values(context.encoder()->slot_count(), value);
            Plaintext pt;
            context.encoder()->encode(values, pt);
            Ciphertext ct;
            context.encryptor()->encrypt_symmetric(pt, ct);
            return ct;
        }
    } // namespace

    TEST(ResultPackageTest, SaveLoadResultPackage)
    {
        ResultPackage rp;
        stringstream ss;

        auto params = get_params();
        auto context(make_shared<CryptoContext>(*params));

        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        // Symmetric encryption
        Ciphertext ct;
        context->encryptor()->encrypt_zero_symmetric(ct);
        rp.psi_result.set(std::move(ct));
        rp.label_byte_count = 1;
        rp.nonce_byte_count = 2;
        size_t out_size = rp.save(ss);
        ResultPackage rp2;
        size_t in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);
        ASSERT_EQ(rp2.label_byte_count, rp.label_byte_count);
        ASSERT_EQ(rp2.nonce_byte_count, rp.nonce_byte_count);
        ASSERT_TRUE(rp2.label_result.empty());
        Plaintext pt;
        context->decryptor()->decrypt(rp2.psi_result.extract_if_local(), pt);
        ASSERT_TRUE(pt.is_zero());

        // Symmetric encryption as Serializable; not used in practice
        auto ser_ct = context->encryptor()->encrypt_zero_symmetric();
        rp.bundle_idx = 1;
        rp.psi_result.set(ser_ct);
        out_size = rp.save(ss);
        in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);
        ASSERT_EQ(rp2.label_byte_count, rp.label_byte_count);
        ASSERT_EQ(rp2.nonce_byte_count, rp.nonce_byte_count);

        // Loaded package can never be serializable
        ASSERT_FALSE(rp2.psi_result.is_serializable());
        ASSERT_TRUE(rp2.label_result.empty());

        // Add some label data as well
        rp.bundle_idx = 2;
        rp.psi_result.set(ser_ct);
        rp.label_result.emplace_back(ser_ct);
        rp.label_result.emplace_back(ser_ct);
        out_size = rp.save(ss);
        in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_EQ(rp2.bundle_idx, rp.bundle_idx);
        ASSERT_EQ(rp2.label_byte_count, rp.label_byte_count);
        ASSERT_EQ(rp2.nonce_byte_count, rp.nonce_byte_count);
        ASSERT_EQ(rp2.label_result.size(), rp.label_result.size());
        context->decryptor()->decrypt(rp2.label_result[0].extract_if_local(), pt);
        ASSERT_TRUE(pt.is_zero());
        context->decryptor()->decrypt(rp2.label_result[1].extract_if_local(), pt);
        ASSERT_TRUE(pt.is_zero());
    }

    TEST(ResultPackageTest, Extract)
    {
        ResultPackage rp;

        auto params = get_params();
        auto context(make_shared<CryptoContext>(*params));

        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        // No labels
        rp.bundle_idx = 123;
        Ciphertext ct;
        context->encryptor()->encrypt_zero_symmetric(ct);
        rp.psi_result.set(ct);

        PlainResultPackage prp = rp.extract(*context);

        // Data has been extracted
        ASSERT_FALSE(rp.psi_result.is_local());
        ASSERT_FALSE(rp.psi_result.is_serializable());

        // bundle_idx is unchanged by extract
        ASSERT_EQ(rp.bundle_idx, prp.bundle_idx);
        ASSERT_EQ(rp.label_byte_count, prp.label_byte_count);
        ASSERT_EQ(rp.nonce_byte_count, prp.nonce_byte_count);
        ASSERT_TRUE(
            all_of(prp.psi_result.begin(), prp.psi_result.end(), [](auto a) { return !a; }));
        ASSERT_TRUE(prp.label_result.empty());

        // Add some label data as well
        rp.psi_result.set(ct);
        rp.label_result.emplace_back(ct);
        rp.label_result.emplace_back(ct);

        prp = rp.extract(*context);

        // Data has been extracted
        ASSERT_FALSE(rp.psi_result.is_local());
        ASSERT_FALSE(rp.psi_result.is_serializable());
        ASSERT_TRUE(rp.label_result.empty());

        ASSERT_EQ(rp.bundle_idx, prp.bundle_idx);
        ASSERT_EQ(rp.label_byte_count, prp.label_byte_count);
        ASSERT_EQ(rp.nonce_byte_count, prp.nonce_byte_count);
        ASSERT_TRUE(
            all_of(prp.psi_result.begin(), prp.psi_result.end(), [](auto a) { return !a; }));
        ASSERT_EQ(2, prp.label_result.size());
        ASSERT_TRUE(all_of(
            prp.label_result[0].begin(), prp.label_result[0].end(), [](auto a) { return !a; }));
        ASSERT_TRUE(all_of(
            prp.label_result[1].begin(), prp.label_result[1].end(), [](auto a) { return !a; }));
    }

    TEST(ResultPackageTest, SaveLoadWithoutPSIResult)
    {
        // A result for parameters with match tags has no PSI result, and its package leaves the
        // field out rather than writing an empty one
        auto context(make_shared<CryptoContext>(*get_tag_params()));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        ResultPackage rp;
        rp.bundle_idx = 1;
        rp.label_byte_count = 0;
        rp.nonce_byte_count = 0;
        for (uint64_t value : { 11U, 22U, 33U }) {
            rp.label_result.emplace_back(encrypt_value(*context, value));
        }

        stringstream ss;
        size_t out_size = rp.save(ss);
        string bytes = ss.str();
        const auto *fbs_rp = fbs::GetSizePrefixedResultPackage(bytes.data());
        ASSERT_EQ(nullptr, fbs_rp->psi_result());
        ASSERT_EQ(3, fbs_rp->label_result()->size());

        ResultPackage rp2;
        size_t in_size = rp2.load(ss, context->seal_context());
        ASSERT_EQ(out_size, in_size);
        ASSERT_FALSE(rp2.psi_result);
        ASSERT_EQ(1, rp2.bundle_idx);
        ASSERT_EQ(3, rp2.label_result.size());

        // Nothing to decrypt for the PSI result; the label results are all there
        PlainResultPackage prp = rp2.extract(*context);
        ASSERT_TRUE(prp.psi_result.empty());
        ASSERT_EQ(3, prp.label_result.size());
        ASSERT_EQ(22, prp.label_result[1][0]);
    }

    TEST(ResultPackageTest, SaveWithPSIResultIsAsInAPSI1x)
    {
        // A package with a PSI result is written exactly as APSI 1.x writes it: in the same order,
        // with the same fields, so with the same bytes
        auto context(make_shared<CryptoContext>(*get_params()));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        Ciphertext psi_ct = encrypt_value(*context, 0);
        Ciphertext label_ct = encrypt_value(*context, 7);

        ResultPackage rp;
        rp.bundle_idx = 0;
        rp.label_byte_count = 5;
        rp.nonce_byte_count = 2;
        rp.psi_result.set(psi_ct);
        rp.label_result.emplace_back(label_ct);
        stringstream ss;
        rp.save(ss);

        vector<unsigned char> psi_bytes = ciphertext_bytes(psi_ct, rp.compr_mode);
        ASSERT_EQ(
            raw_package(0, &psi_bytes, 5, 2, { ciphertext_bytes(label_ct, rp.compr_mode) }),
            ss.str());
    }

    TEST(ResultPackageTest, LoadForTagParamsChecksStructureBeforeCiphertexts)
    {
        auto params = get_tag_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        vector<unsigned char> good_ct =
            ciphertext_bytes(encrypt_value(*context, 1), compr_mode_type::none);
        vector<unsigned char> garbage(100, 0xAB);

        auto load = [&](const string &bytes, const PSIParams *with_params) {
            stringstream ss(bytes);
            ResultPackage rp;
            if (with_params) {
                rp.load(ss, context->seal_context(), *with_params);
            } else {
                rp.load(ss, context->seal_context());
            }
            return rp;
        };
        auto load_error = [&](const string &bytes, const PSIParams *with_params) {
            try {
                static_cast<void>(load(bytes, with_params));
            } catch (const runtime_error &ex) {
                return string(ex.what());
            }
            return string();
        };

        // The structure a result for these parameters has: three tag parts and no label, or
        // three tag parts and as many more as the nonce and label take
        ASSERT_EQ(
            3,
            load(raw_package(1, nullptr, 0, 0, { good_ct, good_ct, good_ct }), params.get())
                .label_result.size());
        size_t payload = ((16 + 10) * 8 + 15) / 16;
        vector<vector<unsigned char>> labeled(3 + payload, good_ct);
        ASSERT_EQ(
            3 + payload,
            load(raw_package(0, nullptr, 10, 16, labeled), params.get()).label_result.size());

        // Ciphertexts that are not ciphertexts at all are noticed only when they are loaded
        vector<vector<unsigned char>> garbage_parts(3, garbage);
        ASSERT_NE(
            string::npos,
            load_error(raw_package(0, nullptr, 0, 0, garbage_parts), params.get())
                .find("failed to load label ciphertext"));

        // Anything structurally wrong is refused before that: the messages name the structure,
        // although every ciphertext is garbage
        vector<string> structural_errors{
            load_error(raw_package(0, &garbage, 0, 0, garbage_parts), params.get()),
            load_error(
                raw_package(0, nullptr, 0, 0, vector<vector<unsigned char>>(2, garbage)),
                params.get()),
            load_error(
                raw_package(0, nullptr, 0, 0, vector<vector<unsigned char>>(4, garbage)),
                params.get()),
            load_error(raw_package(0, nullptr, 10, 16, garbage_parts), params.get()),
            load_error(raw_package(0, nullptr, 0, 4, garbage_parts), params.get()),
            load_error(
                raw_package(0, nullptr, 1025, 0, vector<vector<unsigned char>>(3 + 513, garbage)),
                params.get()),
            load_error(
                raw_package(0, nullptr, 10, 17, vector<vector<unsigned char>>(3 + 14, garbage)),
                params.get()),
            load_error(raw_package(2, nullptr, 0, 0, garbage_parts), params.get()),
        };
        for (const auto &error : structural_errors) {
            ASSERT_NE(string::npos, error.find("failed to load ResultPackage")) << error;
            ASSERT_EQ(string::npos, error.find("ciphertext")) << error;
        }

        // Without parameters nothing more is checked than before: this loads up to its first
        // ciphertext
        ASSERT_NE(
            string::npos,
            load_error(raw_package(0, &garbage, 0, 0, garbage_parts), nullptr).find("ciphertext"));

        // With parameters without match tags, a package without a PSI result is refused before any
        // ciphertext in it is loaded, as the schema refused it before match tags made the PSI
        // result optional. One with a PSI result loads up to its first ciphertext.
        string missing =
            load_error(raw_package(0, nullptr, 0, 4, garbage_parts), get_params().get());
        ASSERT_NE(string::npos, missing.find("PSI result is missing")) << missing;
        ASSERT_EQ(string::npos, missing.find("ciphertext")) << missing;
        ASSERT_NE(
            string::npos,
            load_error(raw_package(0, &garbage, 0, 4, garbage_parts), get_params().get())
                .find("ciphertext"));
    }

    TEST(ResultPackageTest, CheckTagStructure)
    {
        auto params = get_tag_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());
        Ciphertext ct = encrypt_value(*context, 1);

        auto make = [&](uint32_t bundle_idx,
                        bool psi,
                        uint32_t label_bytes,
                        uint32_t nonce_bytes,
                        size_t parts) {
            ResultPackage rp;
            rp.bundle_idx = bundle_idx;
            if (psi) {
                rp.psi_result.set(ct);
            }
            rp.label_byte_count = label_bytes;
            rp.nonce_byte_count = nonce_bytes;
            for (size_t i = 0; i < parts; i++) {
                rp.label_result.emplace_back(ct);
            }
            return rp;
        };

        ASSERT_NO_THROW(make(0, false, 0, 0, 3).check_tag_structure(*params));
        ASSERT_NO_THROW(make(1, false, 10, 16, 3 + 13).check_tag_structure(*params));
        ASSERT_NO_THROW(make(1, false, 1, 0, 3 + 1).check_tag_structure(*params));
        ASSERT_THROW(make(0, true, 0, 0, 3).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 0, 0, 2).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 0, 0, 4).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 10, 16, 3 + 12).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 0, 1, 3).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 1025, 0, 3 + 513).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(0, false, 10, 17, 3 + 14).check_tag_structure(*params), runtime_error);
        ASSERT_THROW(make(2, false, 0, 0, 3).check_tag_structure(*params), runtime_error);

        // Parameters without match tags have no structure to check here
        ASSERT_NO_THROW(make(5, false, 0, 7, 0).check_tag_structure(*get_params()));
    }

    TEST(ResultPackageTest, ExtractTagAndLabelResults)
    {
        auto params = get_tag_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        ResultPackage rp;
        rp.label_byte_count = 1;
        for (uint64_t value : { 1U, 2U, 3U, 4U }) {
            rp.label_result.emplace_back(encrypt_value(*context, value));
        }

        ASSERT_THROW(static_cast<void>(rp.extract_tag_result(*context, 5)), invalid_argument);
        ASSERT_THROW(static_cast<void>(rp.extract_label_result(*context, 5)), invalid_argument);

        // The tag parts come first, and the label parts after them
        auto tags = rp.extract_tag_result(*context, 3);
        ASSERT_EQ(3, tags.size());
        for (uint64_t i = 0; i < 3; i++) {
            ASSERT_EQ(context->encoder()->slot_count(), tags[i].size());
            ASSERT_TRUE(all_of(tags[i].begin(), tags[i].end(), [&](auto a) { return a == i + 1; }));
        }

        // They are moved out, so they cannot be decrypted twice, while the label parts can still
        // be decrypted on their own
        ASSERT_THROW(static_cast<void>(rp.extract_tag_result(*context, 3)), logic_error);
        auto labels = rp.extract_label_result(*context, 3);
        ASSERT_EQ(1, labels.size());
        ASSERT_EQ(4, labels[0][0]);

        // Without tag parts, every label part is a label part
        ResultPackage rp2;
        for (uint64_t value : { 5U, 6U }) {
            rp2.label_result.emplace_back(encrypt_value(*context, value));
        }
        auto all_labels = rp2.extract_label_result(*context, 0);
        ASSERT_EQ(2, all_labels.size());
        ASSERT_EQ(6, all_labels[1][0]);
    }
} // namespace APSITests
