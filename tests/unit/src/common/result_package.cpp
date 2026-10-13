// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/network/result_package.h"
#include "apsi/network/result_package_generated.h"
#include "apsi/psi_params.h"

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/serialization.h"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;
using namespace apsi::network;

namespace APSITests {
    namespace {
        /**
        What Microsoft SEAL throws when it is to load as a ciphertext bytes that are a single value
        repeated, as the garbage in these tests is: it reads them as the header of a version it
        does not know.
        */
        constexpr const char *not_a_ciphertext_error = "incompatible version";

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
        when null. The ciphertexts are raw bytes, which need not be valid ciphertexts. Each is
        written to bytes of its own, as save writes it, unless write_equal_cts_once is set:
        then equal ciphertexts are written once and all point there, as FlatBuffers allows.
        */
        string raw_package(
            uint32_t bundle_idx,
            const vector<unsigned char> *psi_ct,
            uint32_t label_byte_count,
            uint32_t nonce_byte_count,
            const vector<vector<unsigned char>> &label_cts,
            bool write_equal_cts_once = false)
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            map<vector<unsigned char>, flatbuffers::Offset<fbs::Ciphertext>> written;
            auto write_ct = [&](const vector<unsigned char> &ct) {
                auto it = written.find(ct);
                if (it != written.end()) {
                    return it->second;
                }

                auto data = fbs_builder.CreateVector(ct.data(), ct.size());
                auto offset = fbs::CreateCiphertext(fbs_builder, data);
                if (write_equal_cts_once) {
                    written.emplace(ct, offset);
                }
                return offset;
            };

            flatbuffers::Offset<fbs::Ciphertext> psi_ct_offset;
            if (psi_ct) {
                psi_ct_offset = write_ct(*psi_ct);
            }

            auto label_cts_offset = fbs_builder.CreateVector([&] {
                vector<flatbuffers::Offset<fbs::Ciphertext>> ret;
                for (const auto &label_ct : label_cts) {
                    ret.push_back(write_ct(label_ct));
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
        Encrypts a vector of slot values, every slot set to value, at the last level of the modulus
        chain, where a sender's results are.
        */
        Ciphertext encrypt_value(const CryptoContext &context, uint64_t value)
        {
            vector<uint64_t> values(context.encoder()->slot_count(), value);
            Plaintext pt;
            context.encoder()->encode(values, pt);
            Ciphertext ct;
            context.encryptor()->encrypt_symmetric(pt, ct);
            Evaluator(*context.seal_context())
                .mod_switch_to_inplace(ct, context.seal_context()->last_parms_id());
            return ct;
        }

        /**
        Returns a ciphertext of size 2 whose data is zero, at the last level of the modulus chain,
        where a sender's results are.
        */
        Ciphertext zero_result(const CryptoContext &context)
        {
            const auto &seal_context = *context.seal_context();
            Ciphertext ct(seal_context, seal_context.last_parms_id());
            ct.resize(2);
            return ct;
        }

        /**
        Loads the serialized result package, with the given parameters unless they are null, and
        returns the message of the std::runtime_error that throws, or an empty string if it loads.
        */
        string package_load_error(
            const string &bytes, const CryptoContext &context, const PSIParams *params)
        {
            stringstream ss(bytes);
            ResultPackage rp;
            try {
                if (params) {
                    rp.load(ss, context.seal_context(), *params);
                } else {
                    rp.load(ss, context.seal_context());
                }
            } catch (const runtime_error &ex) {
                return ex.what();
            }
            return {};
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

        // Symmetric encryption, at the last level of the modulus chain, where a sender's results
        // are
        auto last_parms_id = context->seal_context()->last_parms_id();
        Ciphertext ct;
        context->encryptor()->encrypt_zero_symmetric(last_parms_id, ct);
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
        auto ser_ct = context->encryptor()->encrypt_zero_symmetric(last_parms_id);
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

        // A package's ciphertexts must take at least 1/64 of the 64 KiB each loads to, so these
        // garbage ciphertexts take 2 KiB each
        vector<unsigned char> good_ct =
            ciphertext_bytes(encrypt_value(*context, 1), compr_mode_type::none);
        vector<unsigned char> garbage(2048, 0xAB);

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
            return package_load_error(bytes, *context, with_params);
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
        const string garbage_psi_error =
            string("failed to load PSI ciphertext: ") + not_a_ciphertext_error;
        const string garbage_label_error =
            string("failed to load label ciphertext: ") + not_a_ciphertext_error;
        vector<vector<unsigned char>> garbage_parts(3, garbage);
        ASSERT_EQ(
            garbage_label_error,
            load_error(raw_package(0, nullptr, 0, 0, garbage_parts), params.get()));

        // Anything structurally wrong is refused before that, although every ciphertext is
        // garbage
        const string refused = "failed to load ResultPackage: result package ";
        vector<pair<string, string>> structural_errors{
            { load_error(raw_package(0, &garbage, 0, 0, garbage_parts), params.get()),
              "has a PSI result, which parameters with match tags rule out" },
            { load_error(
                  raw_package(0, nullptr, 0, 0, vector<vector<unsigned char>>(2, garbage)),
                  params.get()),
              "has 2 label parts but 3 are expected" },
            { load_error(
                  raw_package(0, nullptr, 0, 0, vector<vector<unsigned char>>(4, garbage)),
                  params.get()),
              "has 4 label parts but 3 are expected" },
            { load_error(raw_package(0, nullptr, 10, 16, garbage_parts), params.get()),
              "has 3 label parts but 16 are expected" },
            { load_error(raw_package(0, nullptr, 0, 4, garbage_parts), params.get()),
              "has a nonce_byte_count but no label" },
            { load_error(
                  raw_package(0, nullptr, 1025, 0, vector<vector<unsigned char>>(3 + 513, garbage)),
                  params.get()),
              "has too large a label_byte_count" },
            { load_error(
                  raw_package(0, nullptr, 10, 17, vector<vector<unsigned char>>(3 + 14, garbage)),
                  params.get()),
              "has too large a nonce_byte_count" },
            { load_error(raw_package(2, nullptr, 0, 0, garbage_parts), params.get()),
              "is for bundle index 2 but the parameters have only 2" },
        };
        for (const auto &[error, reason] : structural_errors) {
            ASSERT_EQ(refused + reason, error);
        }

        // Without parameters only what any parameters allow is checked, which this package has:
        // it loads up to its first ciphertext
        ASSERT_EQ(
            garbage_psi_error, load_error(raw_package(0, &garbage, 0, 0, garbage_parts), nullptr));

        // With parameters without match tags, a package without a PSI result is refused before any
        // ciphertext in it is loaded, as APSI 1.x, whose schema requires the PSI result, refuses
        // it. One with a PSI result, and with no more label parts than its 29-byte label and 4-byte
        // nonce take, three of 128 bits, loads up to its first ciphertext.
        ASSERT_EQ(
            string(
                "failed to load ResultPackage: the PSI result is missing, but the parameters do "
                "not use match tags"),
            load_error(raw_package(0, nullptr, 29, 4, garbage_parts), get_params().get()));
        ASSERT_EQ(
            garbage_psi_error,
            load_error(raw_package(0, &garbage, 29, 4, garbage_parts), get_params().get()));
    }

    TEST(ResultPackageTest, LoadRefusesCiphertextsThatCannotBeResults)
    {
        // A sender's results are in coefficient form, at the last level of the modulus chain, and
        // of size 2 or 3. Either size loads whether or not the parameters allow relinearization,
        // as these do. A package holding any other ciphertext is refused as soon as that
        // ciphertext is loaded, before the next.
        auto params = get_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());
        auto seal_context = context->seal_context();
        ASSERT_NE(seal_context->first_parms_id(), seal_context->last_parms_id());
        Evaluator evaluator(*seal_context);

        Ciphertext fresh;
        context->encryptor()->encrypt_zero_symmetric(fresh);
        Ciphertext size_three;
        evaluator.multiply(fresh, fresh, size_three);
        Ciphertext size_four;
        evaluator.multiply(size_three, fresh, size_four);
        ASSERT_EQ(3, size_three.size());
        ASSERT_EQ(4, size_four.size());
        Ciphertext ntt = encrypt_value(*context, 0);
        evaluator.transform_to_ntt_inplace(ntt);
        evaluator.mod_switch_to_inplace(size_three, seal_context->last_parms_id());
        evaluator.mod_switch_to_inplace(size_four, seal_context->last_parms_id());

        vector<unsigned char> good =
            ciphertext_bytes(encrypt_value(*context, 0), compr_mode_type::none);
        vector<unsigned char> garbage(100, 0xAB);
        auto load_error = [&](const string &bytes) {
            return package_load_error(bytes, *context, params.get());
        };

        // Results of size 2 and 3 load
        vector<unsigned char> three = ciphertext_bytes(size_three, compr_mode_type::none);
        ASSERT_EQ(string(), load_error(raw_package(0, &good, 1, 0, { good })));
        ASSERT_EQ(string(), load_error(raw_package(0, &three, 1, 0, { three })));

        // Every other shape is refused, as a PSI result or as a label part, and before the
        // garbage after it is loaded. A 20-byte label takes two label parts of 128 bits.
        vector<pair<vector<unsigned char>, string>> wrong{
            { ciphertext_bytes(fresh, compr_mode_type::none),
              "it is not at the last level of the modulus chain, where a result is" },
            { ciphertext_bytes(size_four, compr_mode_type::none),
              "it has size 4, and a result has size 2 or 3" },
            { ciphertext_bytes(ntt, compr_mode_type::none),
              "it is in NTT form, and a result is in coefficient form" },
        };
        for (const auto &[bytes, reason] : wrong) {
            ASSERT_EQ(
                "failed to load PSI ciphertext: " + reason,
                load_error(raw_package(0, &bytes, 1, 0, { garbage })));
            ASSERT_EQ(
                "failed to load label ciphertext: " + reason,
                load_error(raw_package(0, &good, 20, 0, { bytes, garbage })));
        }
    }

    TEST(ResultPackageTest, LoadWithoutTagsRefusesMoreLabelPartsThanTheLabelTakes)
    {
        // Without match tags a sender sends as many label parts as its label and nonce take, in
        // parts of item_bit_count bits, and none without a label. Every part is loaded and
        // decrypted, so no more are accepted. Fewer are, as by APSI 1.x, which reads short label
        // data as a shorter label.
        auto params = get_params();
        ASSERT_EQ(size_t(128), params->item_bit_count());
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        vector<unsigned char> good =
            ciphertext_bytes(encrypt_value(*context, 0), compr_mode_type::none);
        auto load_error =
            [&](uint32_t label_byte_count, uint32_t nonce_byte_count, size_t part_count) {
                return package_load_error(
                    raw_package(
                        0,
                        &good,
                        label_byte_count,
                        nonce_byte_count,
                        vector<vector<unsigned char>>(part_count, good)),
                    *context,
                    params.get());
            };

        // A 20-byte label and a 4-byte nonce take two parts of 128 bits
        for (size_t part_count = 0; part_count <= 2; part_count++) {
            ASSERT_EQ(string(), load_error(20, 4, part_count)) << part_count;
        }
        ASSERT_EQ(
            string(
                "failed to load ResultPackage: result package has 3 label parts but at most 2 "
                "are expected"),
            load_error(20, 4, 3));

        // Without a label there are none, whatever the nonce_byte_count, which is then not read
        for (uint32_t nonce_byte_count : { 0U, 16U, 17U }) {
            ASSERT_EQ(string(), load_error(0, nonce_byte_count, 0)) << nonce_byte_count;
            ASSERT_EQ(
                string(
                    "failed to load ResultPackage: result package has 1 label parts but at "
                    "most 0 are expected"),
                load_error(0, nonce_byte_count, 1))
                << nonce_byte_count;
        }
    }

    TEST(ResultPackageTest, LoadWithoutParamsRefusesMoreLabelPartsThanAnyParamsAllow)
    {
        // Without parameters, the bound on the label parts is the most any parameters allow:
        // tag_part_count_max = 64 tag parts, and the label and nonce in parts of the smallest
        // item_bit_count, 8 bits. That is 64 parts without a label, and 64 + 1024 + 16 = 1104 at
        // the largest label and nonce.
        auto context(make_shared<CryptoContext>(*get_params()));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        auto load_error = [&](uint32_t label_byte_count,
                              uint32_t nonce_byte_count,
                              const vector<unsigned char> &ct,
                              size_t part_count) {
            return package_load_error(
                raw_package(
                    0,
                    &ct,
                    label_byte_count,
                    nonce_byte_count,
                    vector<vector<unsigned char>>(part_count, ct)),
                *context,
                nullptr);
        };

        // Without a label, a package of 64 parts loads, and one of 65 is refused
        vector<unsigned char> good =
            ciphertext_bytes(encrypt_value(*context, 0), compr_mode_type::none);
        ASSERT_EQ(string(), load_error(0, 0, good, 64));
        ASSERT_EQ(
            string(
                "failed to load ResultPackage: result package has 65 label parts but at most "
                "64 are expected"),
            load_error(0, 0, good, 65));

        // At the largest label and nonce, a package of 1104 parts gets past the bound and fails
        // only when its first ciphertext is loaded, as its ciphertexts are garbage so as not to
        // load so many. One of 1105 parts is refused before that.
        vector<unsigned char> garbage(2048, 0xAB);
        ASSERT_EQ(
            string("failed to load PSI ciphertext: ") + not_a_ciphertext_error,
            load_error(1024, 16, garbage, 1104));
        ASSERT_EQ(
            string(
                "failed to load ResultPackage: result package has 1105 label parts but at "
                "most 1104 are expected"),
            load_error(1024, 16, garbage, 1105));
    }

    TEST(ResultPackageTest, LoadWithoutTagsRefusesABundleIndexTheParamsDoNotHave)
    {
        // With parameters without match tags, as with them, a package for a bundle index the
        // parameters do not have is refused before any ciphertext in it is loaded, here garbage.
        // Without parameters the bundle index cannot be checked, and the package loads.
        auto params = get_params();
        ASSERT_EQ(size_t(1), params->bundle_idx_count());
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        vector<unsigned char> good =
            ciphertext_bytes(encrypt_value(*context, 0), compr_mode_type::none);
        vector<unsigned char> garbage(2048, 0xAB);

        ASSERT_EQ(
            string(), package_load_error(raw_package(0, &good, 0, 0, {}), *context, params.get()));
        ASSERT_EQ(
            string(
                "failed to load ResultPackage: result package is for bundle index 1 but the "
                "parameters have only 1"),
            package_load_error(raw_package(1, &garbage, 0, 0, {}), *context, params.get()));
        ASSERT_EQ(string(), package_load_error(raw_package(1, &good, 0, 0, {}), *context, nullptr));
    }

    TEST(ResultPackageTest, LoadRefusesCiphertextsThatShareBytes)
    {
        // A sender saves every ciphertext to bytes of its own. FlatBuffers lets many offsets point
        // at one object, and its verifier allows it, so a short package could otherwise hold one
        // ciphertext many times over and have the receiver load each. Both overloads of load
        // refuse a package whose label parts share bytes, with match tags or without them.
        auto params = get_params();
        auto tag_params = get_tag_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        vector<unsigned char> psi =
            ciphertext_bytes(encrypt_value(*context, 1), compr_mode_type::none);
        vector<unsigned char> part =
            ciphertext_bytes(encrypt_value(*context, 0), compr_mode_type::none);

        // Without match tags, a 20-byte label takes two parts; with them, the parameters call for
        // three tag parts
        vector<tuple<const PSIParams *, string, string>> packages{
            { params.get(),
              raw_package(0, &psi, 20, 0, { part, part }),
              raw_package(0, &psi, 20, 0, { part, part }, true) },
            { tag_params.get(),
              raw_package(0, nullptr, 0, 0, { part, part, part }),
              raw_package(0, nullptr, 0, 0, { part, part, part }, true) },
        };
        for (const auto &[package_params, honest, shared] : packages) {
            ASSERT_LT(shared.size(), honest.size());
            for (const PSIParams *with_params :
                 { package_params, static_cast<const PSIParams *>(nullptr) }) {
                ASSERT_EQ(string(), package_load_error(honest, *context, with_params));
                ASSERT_EQ(
                    string("failed to load ResultPackage: its ciphertexts share bytes"),
                    package_load_error(shared, *context, with_params));
            }
        }
    }

    TEST(ResultPackageTest, LoadRefusesCiphertextsThatTakeTooFewBytes)
    {
        // SEAL compresses what it saves, so a package of ciphertexts whose data is zero, which are
        // valid results, would load to thousands of times its size. A package's ciphertexts must
        // take at least 1/64 of what they load to: each to 2 * 4096 coefficients of 8 bytes at the
        // last level of the modulus chain, which has one prime.
        if (Serialization::compr_mode_default == compr_mode_type::none) {
            GTEST_SKIP() << "Microsoft SEAL is built without compression";
        }

        auto params = get_params();
        auto tag_params = get_tag_params();
        auto context(make_shared<CryptoContext>(*params));
        KeyGenerator keygen(*context->seal_context());
        context->set_secret(keygen.secret_key());

        vector<unsigned char> zero =
            ciphertext_bytes(zero_result(*context), Serialization::compr_mode_default);
        auto expected_error = [&](size_t ct_count) {
            stringstream ss;
            ss << "failed to load ResultPackage: its ciphertexts take " << ct_count * zero.size()
               << " bytes, less than 1/64 of the " << ct_count * 2 * 4096 * 8
               << " bytes they would load to";
            return ss.str();
        };

        // A package of nothing but zeros is refused before any of its ciphertexts is loaded, with
        // parameters or without them, and with match tags or without them
        string zeros = raw_package(0, &zero, 20, 0, { zero, zero });
        ASSERT_EQ(expected_error(3), package_load_error(zeros, *context, params.get()));
        ASSERT_EQ(expected_error(3), package_load_error(zeros, *context, nullptr));
        string tag_zeros = raw_package(0, nullptr, 0, 0, { zero, zero, zero });
        ASSERT_EQ(expected_error(3), package_load_error(tag_zeros, *context, tag_params.get()));

        // One result can honestly be a ciphertext of zeros: that of a label part whose polynomials
        // are all zero, as they are when the part holds only the last bits of a short label and
        // every item in the bin bundle has zeros there. A 17-byte label takes two parts of 128
        // bits, the second holding only 8 bits. Such a package is accepted, which is why the bound
        // is on the package as a whole rather than on each ciphertext.
        vector<unsigned char> good =
            ciphertext_bytes(encrypt_value(*context, 0), Serialization::compr_mode_default);
        string honest = raw_package(0, &good, 17, 0, { good, zero });
        ASSERT_EQ(string(), package_load_error(honest, *context, params.get()));
        ASSERT_EQ(string(), package_load_error(honest, *context, nullptr));
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
